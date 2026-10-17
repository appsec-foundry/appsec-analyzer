"""Codex adapter contracts with artificial local hosts; no model access."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from runtime.analyst_host import HostCancelled, HostReply, HostTimeout, TransportError
from runtime.assessment_jobs import AssessmentBudget
from runtime.multi_repo_discovery import BudgetExhausted

from appsec_analyzer import cli, codex_cli, profiles

FEATURES = {
    name: False for name in ("shell_tool", "hooks", "apps", "plugins", "multi_agent", "skip_host_skill_discovery")
}


def events(payload):
    return b"\n".join(
        json.dumps(e).encode()
        for e in [
            {"type": "thread.started", "thread_id": "fixture"},
            {"type": "turn.started"},
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": json.dumps({"payload_json": json.dumps(payload)})},
            },
            {"type": "turn.completed", "usage": {"input_tokens": 10, "output_tokens": 10}},
        ]
    )


@pytest.fixture
def transport(tmp_path):
    return codex_cli.CodexCliTransport(
        tmp_path, "gpt-6.1-sol", "medium", {"executable": "codex", "version": "0.163.0", "features": FEATURES}
    )


def test_structured_reply_and_isolated_configuration(transport, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-key")
    monkeypatch.setenv("CODEX_API_KEY", "test-only-other-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.invalid")
    seen = {}

    def run(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        assert Path(kwargs["cwd"]).is_dir()
        schema = Path(argv[argv.index("--output-schema") + 1])
        assert json.loads(schema.read_text())["additionalProperties"] is False
        return 0, events({"artifact": None}), b""

    monkeypatch.setattr(codex_cli, "_run", run)
    result = transport.invoke("trusted", "source", {"type": "object"}, 5, lambda: False)
    assert result.payload == {"artifact": None} and result.usd is None
    assert seen["data"] == b"source"
    assert not {"OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL"} & seen["env"].keys()
    assert "--ignore-user-config" in seen["argv"] and "--ephemeral" in seen["argv"]
    assert 'forced_login_method="chatgpt"' in seen["argv"]
    assert 'model_provider="openai"' in seen["argv"]
    assert 'web_search="disabled"' in seen["argv"]
    assert not Path(seen["cwd"]).exists()


@pytest.mark.parametrize(
    "reply",
    [
        b"{}",
        b"[]",
        b"not json",
        events({}) + b"\n" + events({}),
        events({}).replace(b"agent_message", b"command_execution"),
        events({}).replace(b"turn.completed", b"turn.started"),
    ],
)
def test_invalid_or_tool_output_is_rejected(transport, monkeypatch, reply):
    monkeypatch.setattr(codex_cli, "_run", lambda *a, **k: (0, reply, b""))
    with pytest.raises(TransportError, match="Invalid Codex structured"):
        transport.invoke("trusted", "source", {}, 5, lambda: False)


def test_usage_limit_is_redacted_and_has_no_optional_fallback(transport, monkeypatch):
    failure = json.dumps({"type": "turn.failed", "error": {"message": "usage_limit_reached SOURCE_SECRET"}}).encode()
    monkeypatch.setattr(codex_cli, "_run", lambda *a, **k: (1, failure, b"private stderr"))
    with pytest.raises(TransportError) as caught:
        transport.invoke("trusted", "source", {}, 5, lambda: False)
    assert caught.value.reason == "quota_exhausted"
    assert "SOURCE_SECRET" not in str(caught.value)


@pytest.mark.parametrize("budget,expected", [(None, 0), (20, 2)])
def test_public_subscription_selection(tmp_path, monkeypatch, budget, expected):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(codex_cli, "preflight", lambda **kwargs: {"version": "0.163.0"})
    from orchestrator import orchestration_controller as controller

    observed = {}

    def assess(args, **kwargs):
        observed.update(args=args, profile=kwargs["run_profile"])
        return 0

    monkeypatch.setattr(controller, "assess_main", assess)
    args = ["assess", "--repo", str(tmp_path), "--profile", "codex-cli", "--max-calls", "50"]
    if budget is not None:
        args += ["--budget", str(budget)]
    assert cli.main(args) == expected
    if not expected:
        assert "--hard-budget" not in observed["args"]
        assert observed["profile"]["settings"]["max_calls"] == 50
        assert observed["profile"]["settings"]["budget"] is None
        assert observed["profile"]["settings"]["max_parallel"] == 1


def test_subscription_profiles_reject_unenforceable_options(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    with pytest.raises(profiles.ProfileError, match="max_output_tokens"):
        profiles.resolve_model({"model": "gpt-sol", "max_output_tokens": 10}, "codex-cli")
    with pytest.raises(profiles.ProfileError, match="only with codex-cli"):
        profiles.resolve_scan("codex", max_calls=20)
    with pytest.raises(profiles.ProfileError, match="max_calls"):
        profiles.resolve_scan("codex-cli", max_calls=0)


def subscription_budget(**kwargs):
    return AssessmentBudget(None, None, kwargs.pop("max_calls", 10), 3600, spent_usd=None, subscription=True, **kwargs)


def test_subscription_counts_calls_and_preserves_completion_reserve():
    budget = subscription_budget(max_calls=3)
    budget.plan_completion()

    class Host:
        def invoke(self, *args):
            return HostReply({"ok": True}, None)

    with budget.job("optional", "architect_reviewer", True):
        assert budget.invoke(lambda ceiling: Host(), "", "", {}, 5, lambda: False).usd is None
        with pytest.raises(BudgetExhausted):
            budget.invoke(lambda ceiling: pytest.fail("reserved call dispatched"), "", "", {}, 5, lambda: False)
    assert budget.calls == 1 and budget.spent_usd is None and not budget.failed
    with budget.job("stage2:security-architecture", "secarch_renderer", False):
        budget.invoke(lambda ceiling: Host(), "", "", {}, 5, lambda: False)
    assert budget.calls == 2


def test_subscription_rejects_monetary_reply_and_counts_failure():
    budget = subscription_budget()

    class Host:
        def invoke(self, *args):
            return HostReply({}, 1.0)

    with pytest.raises(TransportError, match="unexpected monetary"):
        budget.invoke(lambda ceiling: Host(), "", "", {}, 5, lambda: False)
    assert budget.calls == 1 and budget.failed


@pytest.mark.parametrize(
    "mode,exception", [("timeout", HostTimeout), ("cancel", HostCancelled), ("overflow", TransportError)]
)
def test_bounded_process_execution(tmp_path, mode, exception):
    code = "import time; time.sleep(10)" if mode != "overflow" else "import sys; sys.stdout.write('x'*2000000)"
    stop = lambda: mode == "cancel"
    with pytest.raises(exception):
        codex_cli._run(
            [sys.executable, "-c", code], cwd=tmp_path, env=codex_cli.environment(), timeout_s=1, should_stop=stop
        )


def test_preflight_rejects_api_login_and_unreviewed_versions(tmp_path, monkeypatch):
    monkeypatch.setattr(codex_cli.shutil, "which", lambda _: "/fixture/codex")

    def run(argv, **kwargs):
        if "--version" in argv:
            return 0, b"codex-cli 0.163.0\n", b""
        if "features" in argv:
            return 0, b"\n".join((k + " stable false").encode() for k in FEATURES), b""
        return 0, b"", b"Logged in using an API key"

    monkeypatch.setattr(codex_cli, "_run", run)
    with pytest.raises(ValueError, match="ChatGPT login"):
        codex_cli.preflight()
    monkeypatch.setattr(codex_cli, "_run", lambda *a, **k: (0, b"codex-cli 0.164.0\n", b""))
    with pytest.raises(ValueError, match="reviewed"):
        codex_cli.preflight()


def test_subscription_controller_publishes_validated_reports(tmp_path, monkeypatch):
    from orchestrator import orchestration_controller as controller
    from runtime import multi_repo_scope

    from tests.test_multi_repo_assessment import FullHost
    from tests.test_multi_repo_controller import checkout

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    run = profiles.resolve_scan("codex-cli", depth="quick", max_calls=1111)
    run["cli_version"] = codex_cli.SUPPORTED_VERSION
    root, output = tmp_path / "app", tmp_path / "out"
    checkout(root)
    host = FullHost()
    real_admit = multi_repo_scope.admit

    def admit(*args, **kwargs):
        host.scope = real_admit(*args, **kwargs)
        return host.scope

    monkeypatch.setattr(multi_repo_scope, "admit", admit)

    class SubscriptionHost:
        def __init__(self, delegate):
            self.delegate = delegate

        def invoke(self, *args):
            return HostReply(self.delegate.invoke(*args).payload, None)

    def factory(role, model, ceiling):
        assert ceiling is None
        assert model == "gpt-6.1-sol"
        return SubscriptionHost(host.factory(role, model, 1))

    result = controller.assess_repositories(
        [
            "--repo",
            str(root),
            "--output",
            str(output),
            "--assessment-depth",
            "quick",
            "--trust-mode",
            "trusted",
        ],
        host_factory=factory,
        progress=lambda text: None,
        run_profile=run,
    )
    assert result["status"] == "complete" and result["spent_usd"] is None and result["calls"] > 0
    state = json.loads((output / ".assessment-state.json").read_text())
    assert state["schema_version"] == 2 and state["accounting"]["spent_usd"] is None
    assert state["operator_profile"]["adapter"] == "codex-cli"
    assert state["identity"]["limits"]["max_calls"] == 1111
    assert (output / "security-assessment.md").is_file()


def test_duplicate_json_fields_are_rejected(transport, monkeypatch):
    # Use an explicit agent message so the duplicate survives JSONL encoding.
    rows = [json.loads(line) for line in events({}).splitlines()]
    rows[2]["item"]["text"] = '{"payload_json":"{}","payload_json":"{}"}'
    reply = b"\n".join(json.dumps(row).encode() for row in rows)
    monkeypatch.setattr(codex_cli, "_run", lambda *a, **k: (0, reply, b""))
    with pytest.raises(TransportError, match="Invalid Codex structured"):
        transport.invoke("trusted", "source", {}, 5, lambda: False)


def test_repository_cannot_supply_the_codex_executable(tmp_path, monkeypatch):
    executable = tmp_path / "codex"
    executable.write_text("fixture executable must never run")
    monkeypatch.setattr(codex_cli.shutil, "which", lambda _: str(executable))
    monkeypatch.setattr(codex_cli, "_run", lambda *a, **k: pytest.fail("source-owned executable ran"))
    with pytest.raises(ValueError, match="outside"):
        codex_cli.preflight(repositories=[tmp_path])


@pytest.mark.skipif(sys.platform != "linux", reason="inspect Linux child process state")
def test_timeout_kills_descendants_after_parent_exit(tmp_path):
    import time

    pid_file = tmp_path / "child.pid"
    child = (
        "import os,signal,time;from pathlib import Path;signal.signal(signal.SIGTERM,signal.SIG_IGN);Path("
        + repr(str(pid_file))
        + ").write_text(str(os.getpid()));time.sleep(20)"
    )
    parent = "import subprocess,sys;subprocess.Popen([sys.executable,'-c'," + repr(child) + "])"
    with pytest.raises(HostTimeout):
        codex_cli._run([sys.executable, "-c", parent], cwd=tmp_path, env=codex_cli.environment(), timeout_s=1)
    pid = int(pid_file.read_text())
    for _ in range(20):
        status = Path(f"/proc/{pid}/stat")
        if not status.exists() or status.read_text().split()[2] == "Z":
            break
        time.sleep(0.05)
    else:
        pytest.fail("Codex descendant survived the exchange timeout")


def test_controller_selects_codex_transport_and_role_settings(tmp_path, monkeypatch):
    from orchestrator import orchestration_controller as controller

    run = profiles.resolve_scan("codex-cli")
    runtime = {"executable": "/fixture/codex", "features": FEATURES, "version": "0.163.0"}
    monkeypatch.setattr(codex_cli, "preflight", lambda **kwargs: runtime)
    factory = controller._assessment_cli_host_factory(tmp_path, run_profile=run)
    host = factory("stride_analyzer", run["models"]["stride_analyzer"]["model"], None)
    assert isinstance(host, codex_cli.CodexCliTransport)
    assert host.model == "gpt-6.1-sol" and host.effort == "medium"


def test_preflight_success_keeps_all_tools_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(codex_cli.shutil, "which", lambda _: "/fixture/codex")

    def run(argv, **kwargs):
        if "--version" in argv:
            return 0, b"codex-cli 0.163.0\n", b""
        if "features" in argv:
            return 0, b"\n".join((k + " stable true").encode() for k in FEATURES), b""
        return 0, b"", b"Logged in using ChatGPT\n"

    monkeypatch.setattr(codex_cli, "_run", run)
    runtime = codex_cli.preflight()
    assert runtime["features"]["skip_host_skill_discovery"] is True
    assert all(value is False for key, value in runtime["features"].items() if key != "skip_host_skill_discovery")


def test_preflight_timeout_is_an_actionable_public_error(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(codex_cli.shutil, "which", lambda _: "/fixture/codex")

    def run(*args, **kwargs):
        raise HostTimeout("fixture")

    monkeypatch.setattr(codex_cli, "_run", run)
    assert cli.main(["scan", "--repo", str(tmp_path), "--profile", "codex-cli"]) == 2
    assert "preflight failed" in capsys.readouterr().err


def test_custom_subscription_profile_defaults_to_serial_processing(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    root = tmp_path / "appsec-analyzer/profiles"
    root.mkdir(parents=True)
    (root / "review.yaml").write_text("schema_version: 1\nmodel_profile: codex-cli\n")
    resolved = profiles.resolve_scan("review")
    assert resolved["settings"]["max_parallel"] == 1
    assert profiles.resolve_scan("review", max_parallel=3)["settings"]["max_parallel"] == 3


def test_cancellation_stops_active_host(tmp_path):
    import time

    started = time.monotonic()
    marker = tmp_path / "started"
    code = "from pathlib import Path;import time;Path(" + repr(str(marker)) + ").touch();time.sleep(20)"
    with pytest.raises(HostCancelled):
        codex_cli._run(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            env=codex_cli.environment(),
            timeout_s=10,
            should_stop=lambda: marker.exists(),
        )
    assert marker.exists() and time.monotonic() - started < 3
