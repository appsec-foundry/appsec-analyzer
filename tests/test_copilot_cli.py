"""Copilot CLI adapter contracts with artificial local hosts; no model access."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
from runtime.analyst_host import HostCancelled, HostTimeout, TransportError

from appsec_analyzer import cli, copilot_cli, profiles


@pytest.fixture
def transport(tmp_path):
    return copilot_cli.CopilotCliTransport(
        tmp_path,
        "gpt-5.4",
        "medium",
        {"executable": "copilot", "version": copilot_cli.SUPPORTED_VERSION},
    )


def test_profile_is_explicit_subscription_and_unqualified(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    result = profiles.resolve_scan("copilot-cli")
    assert result["adapter"] == "copilot-cli"
    assert result["qualified"] is False
    assert result["settings"]["budget"] is None
    assert result["settings"]["max_calls"] == 1000
    assert result["models"]["stride_analyzer"]["model"] == "gpt-5.4"
    assert all("max_output_tokens" not in model for model in result["models"].values())
    assert (
        profiles.resolve_model({"model": "gpt-5.4", "reasoning_effort": "minimal"}, "copilot-cli")["reasoning_effort"]
        == "minimal"
    )
    with pytest.raises(profiles.ProfileError, match="USD"):
        profiles.resolve_scan("copilot-cli", budget=1)
    with pytest.raises(profiles.ProfileError, match="max_output_tokens"):
        profiles.resolve_model({"model": "gpt-5.4", "max_output_tokens": 100}, "copilot-cli")
    with pytest.raises(profiles.ProfileError, match="fixed model"):
        profiles.resolve_model({"model": "auto"}, "copilot-cli")


def test_structured_reply_is_validated_and_cli_is_toolless(transport, monkeypatch):
    monkeypatch.setenv("GH_TOKEN", "artificial-test-token")
    monkeypatch.setenv("COPILOT_GITHUB_TOKEN", "another-artificial-token")
    monkeypatch.setenv("GITHUB_TOKEN", "also-artificial")
    monkeypatch.setenv("OPENAI_API_KEY", "not-forwarded")
    seen = {}

    def run(argv, **kwargs):
        seen.update(argv=argv, **kwargs)
        assert Path(kwargs["cwd"]).is_dir()
        assert kwargs["data"].startswith(b"trusted system")
        assert b'"required":["ok"]' in kwargs["data"]
        return 0, b'{"ok":true}', b""

    monkeypatch.setattr(copilot_cli, "_run", run)
    result = transport.invoke(
        "trusted system",
        "untrusted source",
        {"type": "object", "properties": {"ok": {"const": True}}, "required": ["ok"], "additionalProperties": False},
        5,
        lambda: False,
    )
    assert result.payload == {"ok": True} and result.usd is None
    argv = seen["argv"]
    assert "--prompt" not in argv
    assert b"untrusted source" in seen["data"]
    tools = argv.index("--available-tools")
    assert argv[tools + 1] == "--secret-env-vars"
    assert "--allow-all-tools" not in argv and "--allow-tool" not in argv
    assert "--disable-builtin-mcps" in argv
    assert "--no-custom-instructions" in argv
    assert "--no-remote" in argv and "--no-remote-export" in argv
    assert argv[argv.index("--max-ai-credits") + 1] == "30"
    assert not Path(seen["cwd"]).exists()
    assert "GH_TOKEN" not in seen["env"]
    assert "COPILOT_GITHUB_TOKEN" not in seen["env"]
    assert "GITHUB_TOKEN" not in seen["env"]
    assert "OPENAI_API_KEY" not in seen["env"]


@pytest.mark.parametrize(
    "response",
    [
        b"",
        b"not json",
        b'```json\n{"ok":true}\n```',
        b'{"ok":true,"ok":false}',
        b'{"ok":false}',
        b'{"ok":NaN}',
        b'{"ok":true}\n{"ok":true}',
    ],
)
def test_malformed_ambiguous_or_schema_invalid_response_fails_closed(transport, monkeypatch, response):
    monkeypatch.setattr(copilot_cli, "_run", lambda *args, **kwargs: (0, response, b""))
    schema = {
        "type": "object",
        "properties": {"ok": {"const": True}},
        "required": ["ok"],
        "additionalProperties": False,
    }
    with pytest.raises(TransportError, match="Invalid Copilot structured"):
        transport.invoke("trusted", "source", schema, 5, lambda: False)


def test_remote_schema_reference_is_rejected_before_start(transport, monkeypatch):
    monkeypatch.setattr(
        copilot_cli,
        "_run",
        lambda *args, **kwargs: pytest.fail("unsupported schema must not start Copilot"),
    )
    with pytest.raises(TransportError, match="Unsupported Copilot output contract"):
        transport.invoke("trusted", "source", {"$ref": "https://example.invalid/schema"}, 5, lambda: False)


@pytest.mark.parametrize("reference", ["$dynamicRef", "$recursiveRef"])
def test_remote_dynamic_schema_references_are_rejected_before_start(transport, monkeypatch, reference):
    monkeypatch.setattr(
        copilot_cli,
        "_run",
        lambda *args, **kwargs: pytest.fail("unsupported schema must not start Copilot"),
    )
    with pytest.raises(TransportError, match="Unsupported Copilot output contract"):
        transport.invoke("trusted", "source", {reference: "https://example.invalid/schema"}, 5, lambda: False)


def test_oversized_request_is_rejected_before_start(transport, monkeypatch):
    monkeypatch.setattr(
        copilot_cli,
        "_run",
        lambda *args, **kwargs: pytest.fail("oversized request must not start Copilot"),
    )
    with pytest.raises(TransportError, match="size limit"):
        transport.invoke("trusted", "x" * copilot_cli.MAX_REQUEST_BYTES, {"type": "object"}, 5, lambda: False)


def test_failure_text_is_not_exposed(transport, monkeypatch):
    monkeypatch.setattr(
        copilot_cli,
        "_run",
        lambda *args, **kwargs: (1, b"", b"usage limit SOURCE_SECRET https://private.invalid"),
    )
    with pytest.raises(TransportError) as caught:
        transport.invoke("trusted", "source", {"type": "object"}, 5, lambda: False)
    assert caught.value.reason == "quota_exhausted"
    assert "SOURCE_SECRET" not in str(caught.value)
    assert "private.invalid" not in str(caught.value)


def test_preflight_requires_reviewed_executable_outside_source(tmp_path, monkeypatch):
    monkeypatch.setattr(copilot_cli.shutil, "which", lambda _: "/fixture/copilot")
    monkeypatch.setattr(
        copilot_cli,
        "_run",
        lambda argv, **kwargs: (0, f"GitHub Copilot CLI {copilot_cli.SUPPORTED_VERSION}\n".encode(), b""),
    )
    assert copilot_cli.preflight()["version"] == copilot_cli.SUPPORTED_VERSION
    monkeypatch.setattr(copilot_cli.shutil, "which", lambda _: str(tmp_path / "copilot"))
    with pytest.raises(ValueError, match="outside the analyzed repositories"):
        copilot_cli.preflight(repositories=[str(tmp_path)])
    monkeypatch.setattr(copilot_cli.shutil, "which", lambda _: "/fixture/copilot")
    monkeypatch.setattr(copilot_cli, "_run", lambda *args, **kwargs: (0, b"GitHub Copilot CLI 1.0.0\n", b""))
    with pytest.raises(ValueError, match="reviewed"):
        copilot_cli.preflight()


def test_public_preflight_does_not_claim_copilot_login_or_model_access(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(
        copilot_cli,
        "preflight",
        lambda **kwargs: {"executable": "/fixture/copilot", "version": copilot_cli.SUPPORTED_VERSION},
    )
    assert cli.main(["preflight", "--repo", str(repo), "--profile", "copilot-cli", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["generation_test"] == "not_run"
    assert any("authentication, model access, quota" in item for item in result["limitations"])


@pytest.mark.parametrize("max_calls", [None, 2])
def test_model_preflight_requires_exactly_one_authorized_copilot_exchange(monkeypatch, tmp_path, capsys, max_calls):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(
        copilot_cli,
        "preflight",
        lambda **kwargs: {"executable": "/fixture/copilot", "version": copilot_cli.SUPPORTED_VERSION},
    )
    monkeypatch.setattr(
        copilot_cli.CopilotCliTransport,
        "invoke",
        lambda *args, **kwargs: pytest.fail("unauthorized model test must not invoke Copilot"),
    )
    args = ["preflight", "--repo", str(repo), "--profile", "copilot-cli", "--test-model"]
    if max_calls is not None:
        args.extend(["--max-calls", str(max_calls)])
    assert cli.main(args) == 2
    assert "--max-calls 1" in capsys.readouterr().err


@pytest.mark.parametrize(
    "mode,exception",
    [("timeout", HostTimeout), ("cancel", HostCancelled), ("overflow", TransportError)],
)
def test_bounded_process_execution(tmp_path, mode, exception):
    code = "import time; time.sleep(10)" if mode != "overflow" else "import sys; sys.stdout.write('x'*2000000)"
    should_stop = lambda: mode == "cancel"
    with pytest.raises(exception):
        copilot_cli._run(
            [sys.executable, "-c", code],
            cwd=tmp_path,
            env=copilot_cli.environment(),
            timeout_s=1,
            should_stop=should_stop,
        )


def test_public_assess_selects_copilot_subscription_without_usd(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(
        copilot_cli, "preflight", lambda **kwargs: {"executable": "/fixture/copilot", "version": "1.0.101"}
    )
    from orchestrator import orchestration_controller as controller

    observed = {}

    def assess(args, **kwargs):
        observed.update(args=args, profile=kwargs["run_profile"])
        ns, _ = controller._assessment_argument_parser().parse_known_args(args)
        budget = controller._assessment_budget(
            ns, subscription=True, subscription_label="GitHub Copilot account allowance"
        )
        assert budget.subscription and budget.max_calls == 1000
        assert budget.spent_usd is None and budget.max_parallel == 1
        return 0

    monkeypatch.setattr(controller, "assess_main", assess)
    assert cli.main(["assess", "--repo", str(repo), "--profile", "copilot-cli"]) == 0
    assert observed["profile"]["adapter"] == "copilot-cli"
    assert observed["profile"]["settings"]["budget"] is None
    assert "--hard-budget" not in observed["args"]


def test_public_assess_rejects_usd_budget_for_copilot_before_preflight(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(
        copilot_cli, "preflight", lambda **kwargs: pytest.fail("USD budget conflict must be rejected first")
    )
    assert cli.main(["assess", "--repo", str(repo), "--profile", "copilot-cli", "--budget", "5"]) == 2
