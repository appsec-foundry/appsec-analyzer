"""Offline preflight contracts: no real provider or Git network access."""

from __future__ import annotations

import json
import subprocess
import threading

import pytest

from appsec_analyzer import api_hosts, cli, hosts
from tests.test_api_hosts import _profile


@pytest.fixture
def repository(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root


@pytest.fixture
def metadata(monkeypatch):
    class Connection:
        instances = []
        status = 200
        data = b'{"id":"reviewed-model"}'

        def __init__(self, host, address, timeout):
            self.host, self.address, self.timeout = host, address, timeout
            self.requests = []
            self.connected = False
            self.closed = False
            self.instances.append(self)

        def connect(self):
            self.connected = True

        def request(self, *args, **kwargs):
            self.requests.append((args, kwargs))

        def getresponse(self):
            return self

        def read(self, limit):
            return self.data[:limit]

        def close(self):
            self.closed = True

    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Connection)
    monkeypatch.setattr(api_hosts, "_public_addresses", lambda _: ("203.0.113.5",))
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-preflight-key")
    return Connection


def test_api_metadata_uses_authenticated_get_and_preserves_destination(metadata):
    assert api_hosts.preflight(_profile()) == "model_metadata"
    connection = metadata.instances[0]
    args, kwargs = connection.requests[0]
    assert args == ("GET", "/v1/models/reviewed-model")
    assert kwargs == {"body": None, "headers": {"Authorization": "Bearer synthetic-preflight-key"}}
    assert connection.host == "api.openai.com" and connection.address == "203.0.113.5"
    assert connection.closed


@pytest.mark.parametrize(
    "status,reason",
    [
        (301, "metadata_request_failed"),
        (401, "authentication_failed"),
        (403, "access_denied"),
        (404, "model_metadata_unavailable"),
        (429, "rate_limit"),
        (503, "metadata_request_failed"),
    ],
)
def test_failed_metadata_never_reads_error_body_or_follows_redirect(metadata, status, reason):
    metadata.status = status
    metadata.read = lambda *a: pytest.fail("error bodies must not be read")
    with pytest.raises(api_hosts.ApiTransportError, match=reason):
        api_hosts.preflight(_profile())
    assert len(metadata.instances) == len(metadata.instances[0].requests) == 1


@pytest.mark.parametrize(
    "data",
    [
        b"{}",
        b'{"id":"other-model"}',
        b"[]",
        b"not json",
        b'{"id":"reviewed-model","id":"other"}',
        b"x" * (api_hosts.MAX_REPLY_BYTES + 1),
    ],
)
def test_bad_or_missing_model_metadata_fails_closed(metadata, data):
    metadata.data = data
    with pytest.raises(api_hosts.ApiTransportError):
        api_hosts.preflight(_profile())


def test_missing_credential_never_connects(metadata, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY")
    with pytest.raises(api_hosts.ApiTransportError, match="authentication_failed"):
        api_hosts.preflight(_profile())
    assert not metadata.instances


def test_connection_failure_is_redacted(metadata):
    metadata.request = lambda *a, **kw: (_ for _ in ()).throw(OSError("private-token-or-provider-text"))
    with pytest.raises(api_hosts.ApiTransportError) as caught:
        api_hosts.preflight(_profile())
    assert "private-token" not in str(caught.value)


def test_lite_model_list_and_private_pin_are_used(metadata, monkeypatch):
    monkeypatch.setenv("LITELLM_API_KEY", "synthetic-gateway-key")
    metadata.data = b'{"data":[{"id":"reviewed-model"}]}'
    profile = _profile(
        kind="lite",
        endpoint="https://gateway.example/prefix/v1/responses",
        key_env="LITELLM_API_KEY",
        gateway_route_revision="test",
        deployment_id="test",
        pinned_ip="10.20.30.40",
    )
    assert api_hosts.preflight(profile) == "model_metadata"
    assert metadata.instances[0].requests[0][0] == ("GET", "/prefix/v1/models")
    assert metadata.instances[0].address == "10.20.30.40"


def test_bedrock_tls_check_does_not_claim_authentication(metadata, monkeypatch):
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "synthetic-bedrock-key")
    profile = _profile(
        kind="bedrock",
        endpoint="https://bedrock-runtime.eu-central-1.amazonaws.com",
        key_env="AWS_BEARER_TOKEN_BEDROCK",
    )
    assert api_hosts.preflight(profile) == "tls_only"
    assert metadata.instances[0].connected and not metadata.instances[0].requests


def test_dns_timeout_does_not_send_credentials_after_return(metadata, monkeypatch):
    release = threading.Event()
    finished = threading.Event()

    def resolve(host):
        release.wait(timeout=2)
        finished.set()
        return ("203.0.113.5",)

    monkeypatch.setattr(api_hosts, "_public_addresses", resolve)
    monkeypatch.setattr(api_hosts, "PREFLIGHT_SECONDS", 0.01)
    try:
        with pytest.raises(api_hosts.ApiTransportError, match="timeout"):
            api_hosts.preflight(_profile())
    finally:
        release.set()
    assert finished.wait(timeout=1)
    assert not metadata.instances


def test_api_dns_denial_prevents_connection(metadata, monkeypatch):
    def denied(host):
        raise api_hosts.ApiTransportError("destination_denied")

    monkeypatch.setattr(api_hosts, "_public_addresses", denied)
    with pytest.raises(api_hosts.ApiTransportError, match="destination_denied"):
        api_hosts.preflight(_profile())
    assert not metadata.instances


def test_cli_preflight_never_clones_or_starts_assessment(repository, monkeypatch, capsys):
    cli._engine_imports()
    from orchestrator import orchestration_controller
    from runtime import remote_repositories

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(remote_repositories, "clone", lambda *a: pytest.fail("no clone"))
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda *a, **kw: pytest.fail("no assessment"))
    assert cli.main(["preflight", "--repo", str(repository), "--json", "--quiet"]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    result = json.loads(captured.out)
    assert result["assessment_status"] == "not_run"
    assert result["provider_check"] == "local_configuration"
    assert result["generation_test"] == "not_run"
    assert "unverified" in result["limitations"][0]
    assert sorted(p.name for p in repository.iterdir()) == [".git"]


def test_codex_preflight_displays_completed_checks_and_unverified_access(repository, monkeypatch, capsys):
    from appsec_analyzer import codex_cli

    monkeypatch.setattr(codex_cli, "preflight", lambda **kw: {"version": codex_cli.SUPPORTED_VERSION})
    monkeypatch.setattr(codex_cli.CodexCliTransport, "invoke", lambda *a, **kw: pytest.fail("no model call"))
    assert cli.main(["preflight", "--repo", str(repository), "--profile", "codex-cli", "--json"]) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out)["generation_test"] == "not_run"
    assert captured.err.splitlines() == [
        "Preflight",
        "  ✓ Repository  local Git checkout",
        "  ✓ Codex CLI   0.163.0 · ChatGPT login configured",
        "  · Provider    not tested; no model call before the assessment",
    ]
    assert max(map(len, captured.err.splitlines())) <= 100
    assert str(repository) not in captured.err


def test_assessment_preflight_hands_completed_checks_to_the_console(repository, monkeypatch, capsys):
    from appsec_analyzer import codex_cli

    cli._engine_imports()
    from orchestrator import orchestration_controller

    seen = []
    monkeypatch.setattr(codex_cli, "preflight", lambda **kw: {"version": codex_cli.SUPPORTED_VERSION})
    monkeypatch.setattr(
        orchestration_controller,
        "assess_main",
        lambda request, **kw: seen.append(request.namespace().preflight_checks) or 0,
    )
    assert cli.main(["assess", "--repo", str(repository), "--profile", "codex-cli"]) == 0
    # Shown by the console under the run summary, not as a block before it.
    assert "Preflight" not in capsys.readouterr().err
    assert seen == [
        (
            ("✓", "Repository", "local Git checkout"),
            ("✓", "Codex CLI", "0.163.0 · ChatGPT login configured"),
            ("·", "Provider", "not tested yet; the first model call in Reconnaissance checks it"),
        )
    ]


def test_preflight_failure_has_no_completed_summary(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    assert cli.main(["preflight", "--repo", str(tmp_path / "missing"), "--json"]) == 2
    captured = capsys.readouterr()
    assert "✗ Repository  access check failed" in captured.err
    assert "completed" not in captured.err and "✓" not in captured.err
    assert captured.out == ""


def test_url_preflight_checks_read_access_without_output_or_clone(monkeypatch, capsys):
    cli._engine_imports()
    from runtime import remote_repositories

    seen = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(remote_repositories, "check_access", lambda remote: seen.append(remote.url))
    monkeypatch.setattr(remote_repositories, "clone", lambda *a: pytest.fail("no clone"))
    assert cli.main(["preflight", "--repo", "https://git.example/team/source.git", "--json"]) == 0
    assert seen == ["https://git.example/team/source.git"]
    assert "source.git" not in capsys.readouterr().out


def test_default_api_preflight_checks_all_models_without_generation(repository, metadata, monkeypatch, capsys):
    from appsec_analyzer import profiles

    def read(self, limit):
        return json.dumps({"id": self.requests[0][0][1].rsplit("/", 1)[-1]}).encode()

    metadata.read = read
    monkeypatch.setattr(api_hosts.ResponsesTransport, "invoke", lambda *a, **kw: pytest.fail("no generation"))
    assert cli.main(["preflight", "--repo", str(repository), "--profile", "codex", "--json", "--quiet"]) == 0
    expected = {row["model"] for row in profiles.resolve_scan("codex")["models"].values()}
    assert {connection.requests[0][0][1].rsplit("/", 1)[-1] for connection in metadata.instances} == expected
    assert len(metadata.instances) == len(expected)
    assert json.loads(capsys.readouterr().out)["provider_check"] == "model_metadata"


def test_rejected_api_credential_stops_before_checkout(repository, metadata, monkeypatch, capsys):
    cli._engine_imports()
    from runtime import remote_repositories

    metadata.status = 401
    monkeypatch.setattr(remote_repositories, "checkout_arguments", lambda *a: pytest.fail("no checkout"))
    assert cli.main(["assess", "--repo", str(repository), "--profile", "codex"]) == 2
    captured = capsys.readouterr()
    assert "authentication_failed" in captured.err
    assert "synthetic-preflight-key" not in captured.err + captured.out


def test_cancelled_preflight_returns_130(repository, monkeypatch):
    def cancelled():
        raise KeyboardInterrupt

    monkeypatch.setattr(hosts, "claude_preflight", cancelled)
    assert cli.main(["preflight", "--repo", str(repository)]) == 130


@pytest.mark.parametrize("command", ["assess", "preflight"])
def test_invalid_local_source_stops_before_controller(tmp_path, monkeypatch, command):
    cli._engine_imports()
    from orchestrator import orchestration_controller

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda *a, **kw: pytest.fail("no assessment"))
    assert cli.main([command, "--profile", "claude", "--repo", str(tmp_path / "missing")]) == 2


def test_failed_remote_stops_before_any_clone_or_assessment(monkeypatch, tmp_path):
    cli._engine_imports()
    from runtime import remote_repositories

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)

    def fail(remote):
        raise remote_repositories.RemoteError("Git preflight failed")

    monkeypatch.setattr(remote_repositories, "check_access", fail)
    monkeypatch.setattr(remote_repositories, "clone", lambda *a: pytest.fail("no clone"))
    assert (
        cli.main(["assess", "--repo", "https://git.example/team/source.git", "--output", str(tmp_path / "output")]) == 2
    )
    assert not (tmp_path / "output").exists()


def test_remote_checkout_is_a_preflight_row_and_the_summary_names_the_url(monkeypatch, tmp_path):
    from appsec_analyzer import codex_cli

    cli._engine_imports()
    from orchestrator import orchestration_controller
    from runtime import remote_repositories

    url = "https://git.example/team/source.git"
    seen = []
    monkeypatch.setattr(codex_cli, "preflight", lambda **kw: {"version": codex_cli.SUPPORTED_VERSION})
    monkeypatch.setattr(remote_repositories.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(remote_repositories, "check_access", lambda remote: None)
    monkeypatch.setattr(remote_repositories, "clone", lambda remote, root: root.mkdir())
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda request, **kw: seen.append(request) or 0)
    output = tmp_path / "output"
    assert cli.main(["assess", "--repo", url, "--profile", "codex-cli", "--output", str(output)]) == 0
    options = seen[0].options
    assert [label for _, label, _ in options.preflight_checks] == ["Repository", "Checkout", "Codex CLI", "Provider"]
    assert options.preflight_checks[1] == (
        "✓",
        "Checkout",
        "shallow HTTPS clone into a temporary directory, removed after the run",
    )
    # The controller reads the temporary checkout; the summary names what the operator selected.
    assert options.repo != (url,) and options.repo_sources == (url,)


def test_live_probe_requires_explicit_budget(repository, monkeypatch):
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    from appsec_analyzer import preflight

    monkeypatch.setattr(preflight, "_test_model", lambda *a, **kw: pytest.fail("no spending without budget"))
    assert cli.main(["preflight", "--repo", str(repository), "--test-model"]) == 2


def test_subscription_probe_requires_explicit_call_limit(repository, monkeypatch):
    from appsec_analyzer import codex_cli, preflight

    monkeypatch.setattr(codex_cli, "preflight", lambda **kw: {"version": codex_cli.SUPPORTED_VERSION})
    monkeypatch.setattr(preflight, "_test_model", lambda *a, **kw: pytest.fail("no unapproved plan use"))
    assert cli.main(["preflight", "--repo", str(repository), "--profile", "codex-cli", "--test-model"]) == 2


def test_api_probe_uses_selected_primary_model_and_output_bound(repository, metadata, monkeypatch):
    cli._engine_imports()
    from runtime.analyst_host import HostReply

    from appsec_analyzer import profiles

    expected = profiles.resolve_scan("codex")["models"]["stride_analyzer"]["model"]
    seen = []

    def invoke(self, system, prompt, schema, timeout, should_stop):
        assert self.profile.model == expected
        assert self.profile.max_output_tokens == 1024 and self.ceiling == 0.1
        assert prompt == 'Return {"ok": true}.' and timeout == 30
        seen.append(prompt)
        return HostReply(payload={"ok": True}, usd=0.001)

    monkeypatch.setattr(api_hosts.ResponsesTransport, "invoke", invoke)
    assert (
        cli.main(["preflight", "--repo", str(repository), "--profile", "codex", "--test-model", "--budget", "0.1"]) == 0
    )
    assert len(seen) == 1
    assert all(connection.connected and not connection.requests for connection in metadata.instances)


@pytest.mark.parametrize("payload", [{"ok": 1}, {"ok": False}, {"ok": True, "tool": "execute"}, None])
def test_generation_probe_rejects_invalid_or_action_payload(repository, monkeypatch, payload):
    cli._engine_imports()
    from runtime.analyst_host import ClaudeCliTransport, HostReply

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(ClaudeCliTransport, "invoke", lambda *a, **kw: HostReply(payload=payload, usd=0.001))
    assert cli.main(["preflight", "--repo", str(repository), "--test-model", "--budget", "0.1"]) == 2


def test_opt_in_probe_has_only_synthetic_content_and_bounded_budget(repository, monkeypatch, capsys):
    cli._engine_imports()
    from runtime.analyst_host import ClaudeCliTransport, HostReply

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    seen = []

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        assert self.max_budget_usd == 0.1 and timeout_s == 30
        assert self.read_root is None and str(repository) not in str(self.work_dir)
        assert prompt == 'Return {"ok": true}.' and "tools" not in schema
        seen.append(self.model)
        return HostReply(payload={"ok": True}, usd=0.001)

    monkeypatch.setattr(ClaudeCliTransport, "invoke", invoke)
    assert cli.main(["preflight", "--repo", str(repository), "--test-model", "--budget", "0.1", "--json"]) == 0
    assert len(seen) == 1
    assert json.loads(capsys.readouterr().out)["generation_test"] == "primary_model_passed"


def _record_assessment(monkeypatch, events):
    cli._engine_imports()
    from orchestrator import orchestration_controller

    def assess(request, **kw):
        events.append(("assess", request.namespace().preflight_checks))
        return 0

    monkeypatch.setattr(orchestration_controller, "assess_main", assess)


def test_assess_tests_haiku_before_the_run_with_its_own_limit(repository, model_test, monkeypatch, capsys):
    cli._engine_imports()
    from runtime.analyst_host import ClaudeCliTransport, HostReply

    events = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        assert self.model == "haiku" and self.max_budget_usd == 0.05 and self.effort is None
        assert prompt == 'Return {"ok": true}.' and "tools" not in schema and timeout_s == 30
        assert self.read_root is None and str(repository) not in str(self.work_dir)
        events.append(("test", self.model))
        return HostReply(payload={"ok": True}, usd=0.0004)

    monkeypatch.setattr(ClaudeCliTransport, "invoke", invoke)
    _record_assessment(monkeypatch, events)
    # Thorough depth analyzes with Opus; the test still uses the low-cost model.
    assert cli.main(["assess", "--repo", str(repository), "--assessment-depth", "thorough"]) == 0
    assert [kind for kind, _ in events] == ["test", "assess"]
    checks = events[1][1]
    assert ("✓", "Model test", "haiku answered · USD 0.0004") in checks
    assert (
        "·",
        "Provider",
        "only the test model answered; the run's own models answer for the first time in the run",
    ) in checks
    err = capsys.readouterr().err
    assert "Model test: haiku at claude-cli: fixed synthetic prompt only, no repository content" in err
    assert "own limit USD 0.05 outside the run budget" in err


def test_assess_tests_luna_through_the_api_after_every_role_model_check(repository, metadata, model_test, monkeypatch):
    cli._engine_imports()
    from runtime.analyst_host import HostReply

    from appsec_analyzer import profiles

    def read(self, limit):
        return json.dumps({"id": self.requests[0][0][1].rsplit("/", 1)[-1]}).encode()

    metadata.read = read
    events = []

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        assert self.profile.model == "gpt-6-luna" and self.profile.reasoning_effort == "low"
        assert self.profile.max_output_tokens == 1024 and self.ceiling == 0.05
        events.append(("test", self.profile.model))
        return HostReply(payload={"ok": True}, usd=0.0002)

    monkeypatch.setattr(api_hosts.ResponsesTransport, "invoke", invoke)
    _record_assessment(monkeypatch, events)
    assert cli.main(["assess", "--repo", str(repository), "--profile", "codex"]) == 0
    expected = {row["model"] for row in profiles.resolve_scan("codex")["models"].values()}
    assert {connection.requests[0][0][1].rsplit("/", 1)[-1] for connection in metadata.instances} == expected
    assert [kind for kind, _ in events] == ["test", "assess"]


def test_codex_assess_tests_luna_with_one_plan_exchange(repository, model_test, monkeypatch, capsys):
    cli._engine_imports()
    from runtime.analyst_host import HostReply

    from appsec_analyzer import codex_cli

    monkeypatch.setattr(codex_cli, "preflight", lambda **kw: {"version": codex_cli.SUPPORTED_VERSION})
    events = []

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        events.append(("test", self.model, self.effort))
        return HostReply(payload={"ok": True})

    monkeypatch.setattr(codex_cli.CodexCliTransport, "invoke", invoke)
    _record_assessment(monkeypatch, events)
    assert cli.main(["assess", "--repo", str(repository), "--profile", "codex-cli"]) == 0
    assert events[0] == ("test", "gpt-6-luna", "low") and events[1][0] == "assess"
    assert ("✓", "Model test", "gpt-6-luna answered") in events[1][1]
    assert "one exchange from ChatGPT plan allowance" in capsys.readouterr().err


def test_copilot_assess_has_no_model_test(repository, model_test, monkeypatch, tmp_path):
    cli._engine_imports()
    from appsec_analyzer import copilot_cli

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(copilot_cli, "preflight", lambda **kw: {"executable": "/fixture/copilot", "version": "1.0.101"})
    monkeypatch.setattr(copilot_cli.CopilotCliTransport, "invoke", lambda *a, **kw: pytest.fail("no Copilot session"))
    events = []
    _record_assessment(monkeypatch, events)
    assert cli.main(["assess", "--repo", str(repository), "--profile", "copilot-cli"]) == 0
    assert [label for _, label, _ in events[0][1]] == ["Repository", "Copilot CLI", "Provider"]


@pytest.mark.parametrize(
    ("reason", "status"),
    [
        ("authentication_failed", 401),
        ("authentication_failed", 403),
        ("authentication_failed", None),
        ("billing_error", 402),
        ("quota_exhausted", None),
    ],
)
def test_definite_setup_failure_stops_assess_before_checkout(
    repository, model_test, monkeypatch, capsys, reason, status
):
    cli._engine_imports()
    from runtime import remote_repositories
    from runtime.analyst_host import ClaudeCliTransport, TransportError

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)

    def invoke(self, *args):
        raise TransportError("provider detail sk-synthetic", reason=reason, http_status=status)

    monkeypatch.setattr(ClaudeCliTransport, "invoke", invoke)
    monkeypatch.setattr(remote_repositories, "checkout_arguments", lambda *a, **kw: pytest.fail("no checkout"))
    assert cli.main(["assess", "--repo", str(repository)]) == 2
    err = capsys.readouterr().err
    assert f"Preflight model test failed ({reason})" in err
    assert "sk-synthetic" not in err and "provider detail" not in err


@pytest.mark.parametrize(
    ("outcome", "label"),
    [
        (("rate_limit", None), "rate_limit"),
        (("timeout", None), "timeout"),
        (("budget_exhausted", None), "budget_exhausted"),
        (("error_max_budget_usd", None), "error_max_budget_usd"),
        (("provider prose", None), "host_failure"),
        ("host_timeout", "no answer"),
        ("invalid_payload", "invalid_response"),
    ],
)
def test_inconclusive_model_test_warns_and_the_assessment_continues(
    repository, model_test, monkeypatch, outcome, label
):
    cli._engine_imports()
    from runtime.analyst_host import ClaudeCliTransport, HostReply, HostTimeout, TransportError

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)

    def invoke(self, *args):
        if outcome == "host_timeout":
            raise HostTimeout("no answer within the limit")
        if outcome == "invalid_payload":
            return HostReply(payload={"ok": False})
        raise TransportError("detail", reason=outcome[0], http_status=outcome[1])

    monkeypatch.setattr(ClaudeCliTransport, "invoke", invoke)
    events = []
    _record_assessment(monkeypatch, events)
    assert cli.main(["assess", "--repo", str(repository)]) == 0
    assert [kind for kind, _ in events] == ["assess"]
    assert ("⚠", "Model test", f"haiku: inconclusive ({label}); the run continues") in events[0][1]


def test_skip_preflight_starts_the_assessment_without_access_provider_or_model_checks(
    model_test, monkeypatch, tmp_path
):
    cli._engine_imports()
    from orchestrator import orchestration_controller
    from runtime import remote_repositories
    from runtime.analyst_host import ClaudeCliTransport

    url = "https://git.example/team/source.git"
    seen = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(remote_repositories, "check_access", lambda remote: pytest.fail("no access check"))
    monkeypatch.setattr(ClaudeCliTransport, "invoke", lambda *a, **kw: pytest.fail("no model test"))
    monkeypatch.setattr(remote_repositories.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(remote_repositories, "clone", lambda remote, root: seen.append("clone") or root.mkdir())
    monkeypatch.setattr(orchestration_controller, "assess_main", lambda request, **kw: seen.append(request) or 0)
    output = tmp_path / "output"
    assert cli.main(["assess", "--repo", url, "--output", str(output), "--skip-preflight"]) == 0
    # The clone and the controller's admission checks still run; the controller never sees the option.
    assert seen[0] == "clone"
    request = seen[1]
    assert request.options.preflight_checks[-1] == (
        "⚠",
        "Checks",
        "skipped (--skip-preflight); access, provider and model errors show up later",
    )
    assert "--skip-preflight" not in request.arguments
