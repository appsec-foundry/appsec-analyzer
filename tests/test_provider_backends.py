"""Offline provider admission, wire protocols, budgets and controller contracts."""

from __future__ import annotations

import copy
import json
import subprocess

import pytest
import yaml

from appsec_analyzer import api_hosts, cli, profiles
from tests.test_api_hosts import _Connection, _Reply, _response


@pytest.fixture
def connections(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    home = profiles.config_home()
    home.mkdir(parents=True)
    model = {
        "model": "claude",
        "max_output_tokens": 4096,
        "input_usd_per_million": 3.0,
        "output_usd_per_million": 15.0,
        "model_family": "non-opus",
    }
    document = {
        "schema_version": 1,
        "lite": {
            "endpoint": "https://gateway.example/v1/responses",
            "route_revision": "deployment-1",
            "price_revision": "test-prices-1",
            "models": {"claude": {**model, "deployment_id": "sonnet-deployment-1"}},
        },
        "bedrock": {
            "region": "eu-central-1",
            "route_revision": "models-1",
            "price_revision": "test-prices-1",
            "models": {"claude": {**model, "model": "anthropic.claude-sonnet-4-6"}},
        },
    }
    path = home / "providers.yaml"
    path.write_text(yaml.safe_dump(document))
    path.chmod(0o600)
    return path, document


@pytest.fixture
def wire(monkeypatch):
    class Reply(_Reply):
        headers = {"x-litellm-model-id": "sonnet-deployment-1", "x-litellm-response-cost": "0.001"}

        def getheader(self, name):
            return self.headers.get(name)

    class Connection(_Connection):
        instances = []
        response = _response({"accepted": True})
        status = 200

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.reply = Reply(self.response, self.status)

        def request(self, method, path, body, headers):
            if method == "GET":
                self.requests.append((method, path, None, headers))
                self.reply = Reply(b'{"data":[{"id":"claude"},{"id":"small-model"}]}', self.status)
            else:
                super().request(method, path, body, headers)

        def connect(self):
            pass

    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", Connection)
    monkeypatch.setattr(api_hosts, "_public_addresses", lambda host: ("203.0.113.1",))
    monkeypatch.setenv("LITELLM_API_KEY", "artificial-gateway-test-token")
    monkeypatch.setenv("AWS_BEARER_TOKEN_BEDROCK", "artificial-bedrock-test-token")
    return Connection, Reply


def invoke(provider, wire):
    selected = profiles.resolve_scan(provider)
    return api_hosts.ResponsesTransport(profiles.api_profile(selected["models"]["stride_analyzer"]), 2).invoke(
        "analysis instructions", "untrusted repository excerpt", {"type": "object"}, 3, lambda: False
    )


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
@pytest.mark.parametrize("depth", profiles.DEPTHS)
def test_provider_profiles_resolve_offline_at_all_depths(connections, monkeypatch, provider, depth):
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    monkeypatch.delenv("AWS_BEARER_TOKEN_BEDROCK", raising=False)
    result = profiles.resolve_scan(provider, depth=depth)
    assert set(result["models"]) == set(profiles.ROLES)
    assert result["adapter"] == provider and result["qualified"] is False
    assert str(connections[0]) in result["files"]
    assert all(row["requested_model"] == f"{provider} claude" for row in result["models"].values())
    assert profiles.call_reservation(result) > 0


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
def test_custom_profile_can_select_provider_models_per_role(connections, provider):
    path, document = connections
    document[provider]["models"]["small"] = {**document[provider]["models"]["claude"], "model": "small-model"}
    path.write_text(yaml.safe_dump(document))
    home = path.parent
    (home / "model-profiles").mkdir()
    (home / "profiles").mkdir()
    (home / "model-profiles/team.yaml").write_text(
        yaml.safe_dump(
            {
                "schema_version": 1,
                "base": provider,
                "roles": {"recon_scanner": {"model": f"{provider} small", "max_output_tokens": 2048}},
            }
        )
    )
    (home / "profiles/team.yaml").write_text("schema_version: 1\nmodel_profile: team\n")
    run = profiles.resolve_scan("team")
    assert run["models"]["recon_scanner"]["model"] == "small-model"
    assert run["models"]["recon_scanner"]["max_output_tokens"] == 2048
    assert run["models"]["stride_analyzer"]["requested_model"] == f"{provider} claude"


@pytest.mark.parametrize(
    "arguments",
    [
        ["--model", "lite claude"],
        ["--profile", "lite", "--model", "lite claude"],
        ["--profile", "lite claude"],
        ["--profile", "bedrock", "--model", "bedrock claude"],
        ["--profile", "bedrock claude"],
    ],
)
def test_cli_prefix_reaches_controller(connections, wire, tmp_path, monkeypatch, arguments):
    cli._engine_imports()
    from orchestrator import orchestration_controller as controller

    seen = []
    monkeypatch.setattr(controller, "assess_main", lambda args, **kw: seen.append(kw) or 0)
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    assert cli.main(["assess", "--repo", str(repo), *arguments]) == 0
    expected = "bedrock" if any("bedrock" in arg for arg in arguments) else "lite"
    assert seen[0]["run_profile"]["adapter"] == expected
    assert seen[0]["api_profile"].kind == expected


@pytest.mark.parametrize("selection", ["lite claude", "bedrock claude"])
def test_profile_commands_need_no_model_access(connections, monkeypatch, capsys, selection):
    monkeypatch.setattr(api_hosts.ResponsesTransport, "invoke", lambda *a: pytest.fail("no model access"))
    assert cli.main(["profiles", "show", selection]) == 0
    assert json.loads(capsys.readouterr().out)["adapter"] == selection.split()[0]
    assert cli.main(["profiles", "validate", selection]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True


@pytest.mark.parametrize("provider,env", [("lite", "LITELLM_API_KEY"), ("bedrock", "AWS_BEARER_TOKEN_BEDROCK")])
@pytest.mark.parametrize("value", [None, "", "token\r\ninjected: yes", "token with spaces"])
def test_invalid_credentials_stop_before_checkout(connections, provider, env, value, monkeypatch, capsys):
    cli._engine_imports()
    from runtime import remote_repositories

    monkeypatch.setattr(remote_repositories, "checkout_arguments", lambda *a: pytest.fail("no checkout"))
    if value is None:
        monkeypatch.delenv(env, raising=False)
    else:
        monkeypatch.setenv(env, value)
    assert cli.main(["assess", "--profile", provider]) == 2
    assert env in capsys.readouterr().err


@pytest.mark.parametrize(
    "patch",
    [
        {"endpoint": "http://gateway.example/v1/responses"},
        {"endpoint": "https://user:token@gateway.example/v1/responses"},
        {"endpoint": "https://gateway.example/a/../v1/responses"},
        {"endpoint": "https://gateway.example/%2e%2e/v1/responses"},
        {"endpoint": "https://gateway.example/v1/responses?target=elsewhere"},
        {"endpoint": "https://gateway.example:8443/v1/responses"},
        {"pinned_ip": "169.254.169.254"},
        {"pinned_ip": "127.0.0.1"},
        {"pinned_ip": "::1"},
        {"pinned_ip": "::"},
        {"pinned_ip": "224.0.0.1"},
        {"pinned_ip": "ff02::1"},
        {"api_key": "artificial-misplaced-private-value"},
        {"route_revision": ""},
    ],
)
def test_unsafe_operator_connections_are_rejected(connections, patch):
    path, document = connections
    document["lite"].update(patch)
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(profiles.ProfileError):
        profiles.resolve_scan("lite")


@pytest.mark.parametrize(
    "patch",
    [
        {"region": "metadata.internal"},
        {"region": "us-east-1/../../"},
        {"endpoint": "https://not-aws.example"},
    ],
)
def test_bedrock_connection_cannot_redirect_sources(connections, patch):
    path, document = connections
    document["bedrock"].update(patch)
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(profiles.ProfileError):
        profiles.resolve_scan("bedrock")


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
def test_connection_cannot_be_owned_by_source_or_linked(connections, provider, tmp_path):
    path, _ = connections
    with pytest.raises(profiles.ProfileError, match="outside"):
        profiles.resolve_scan(provider, repositories=[path.parent])
    external = tmp_path / "external.yaml"
    path.rename(external)
    path.symlink_to(external)
    with pytest.raises(profiles.ProfileError, match="symlinks"):
        profiles.resolve_scan(provider)


@pytest.mark.parametrize("model", ["lite unknown", "lite ../claude", "lite  claude", "lite claude\n", "bedrock claude"])
def test_lite_selection_rejects_unknown_ambiguous_or_cross_provider_models(connections, model):
    with pytest.raises(profiles.ProfileError):
        profiles.resolve_scan("lite", model_override=model)


def test_prefix_cannot_override_an_explicit_provider(connections):
    with pytest.raises(profiles.ProfileError, match="conflicts"):
        profiles.resolve_scan("codex", model_override="lite claude")


def test_lite_wire_checks_deployment_and_uses_gateway_charge(connections, wire):
    response = invoke("lite", wire)
    assert response.payload == {"accepted": True} and response.usd == 0.001
    method, path, body, headers = wire[0].instances[0].requests[0]
    assert method == "POST" and path == "/v1/responses" and body["model"] == "claude"
    assert body["store"] is False and "tools" not in body
    assert body["text"]["format"]["strict"] is True
    assert headers["Authorization"] == "Bearer artificial-gateway-test-token"
    assert body["num_retries"] == 0 and body["disable_fallbacks"] is True
    assert headers["x-litellm-num-retries"] == "0"


@pytest.mark.parametrize("charge", ["0", "0.0001"])
def test_lite_gateway_charge_below_configured_rates_counts_configured_cost(connections, wire, charge):
    wire[1].headers = {**wire[1].headers, "x-litellm-response-cost": charge}
    response = invoke("lite", wire)
    assert response.usd == pytest.approx((100 * 3.0 + 20 * 15.0) / 1_000_000)


@pytest.mark.parametrize(
    "header,value",
    [
        ("x-litellm-model-id", "unexpected-fallback"),
        ("x-litellm-model-id", None),
        ("x-litellm-response-cost", None),
        ("x-litellm-response-cost", "nan"),
        ("x-litellm-response-cost", "-1"),
        ("x-litellm-response-cost", "1e999"),
        ("x-litellm-response-cost", "3"),
    ],
)
def test_lite_unknown_route_or_cost_never_becomes_an_accepted_answer(connections, wire, header, value):
    wire[1].headers = {**wire[1].headers, header: value}
    with pytest.raises(api_hosts.ApiTransportError, match="invalid_response"):
        invoke("lite", wire)


def bedrock_response(**updates):
    return {
        "stopReason": "end_turn",
        "usage": {"inputTokens": 100, "outputTokens": 20},
        "output": {
            "message": {
                "role": "assistant",
                "content": [
                    {"text": json.dumps({"payload_json": json.dumps({"accepted": True})})},
                ],
            }
        },
        **updates,
    }


def test_bedrock_converse_wire_and_accounting(connections, wire):
    wire[0].response = json.dumps(bedrock_response()).encode()
    result = invoke("bedrock", wire)
    assert result.payload == {"accepted": True}
    assert result.usd == pytest.approx(0.0006)
    method, path, body, headers = wire[0].instances[0].requests[0]
    assert method == "POST" and path == "/model/anthropic.claude-sonnet-4-6/converse"
    assert body["inferenceConfig"]["maxTokens"] == 4096
    assert body["system"] and body["messages"][0]["role"] == "user"
    assert "toolConfig" not in body and "tools" not in body
    assert body["outputConfig"]["textFormat"]["type"] == "json_schema"
    assert headers["Authorization"] == "Bearer artificial-bedrock-test-token"


@pytest.mark.parametrize(
    "update",
    [
        {"stopReason": "max_tokens"},
        {"stopReason": "tool_use"},
        {"stopReason": "guardrail_intervened"},
        {"usage": {}},
        {"usage": {"inputTokens": True, "outputTokens": 20}},
        {"usage": {"inputTokens": 100, "outputTokens": 9000}},
        {"usage": {"inputTokens": 100, "outputTokens": 20, "cacheWriteInputTokens": 100}},
        {"output": {"message": {"role": "assistant", "content": [{"toolUse": {}}]}}},
    ],
)
def test_bedrock_rejects_incomplete_tool_or_unaccounted_responses(connections, wire, update):
    wire[0].response = json.dumps(bedrock_response(**update)).encode()
    with pytest.raises(api_hosts.ApiTransportError):
        invoke("bedrock", wire)


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
def test_provider_does_not_follow_redirects(connections, wire, provider):
    wire[0].status = 302
    with pytest.raises(api_hosts.ApiTransportError, match="invalid_request"):
        invoke(provider, wire)
    assert len(wire[0].instances) == 1


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
def test_changed_connection_cannot_resume_saved_work(connections, provider, tmp_path, monkeypatch):
    from runtime import assessment_state

    path, document = connections
    saved = profiles.resolve_scan(provider)
    output = tmp_path / "out"
    output.mkdir()
    (output / assessment_state.STATE_NAME).write_text("{}")
    monkeypatch.setattr(assessment_state, "_read_state", lambda p: {"operator_profile": saved})
    assert profiles.restore_profile(profiles.resolve_scan(provider), output, resume=True) == saved
    document[provider]["route_revision"] = "changed-route"
    path.write_text(yaml.safe_dump(document))
    with pytest.raises(profiles.ProfileError, match="changed"):
        profiles.restore_profile(profiles.resolve_scan(provider), output, resume=True)


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
@pytest.mark.parametrize("family", [None, "opus", "non-opus"])
def test_provider_models_preserve_organization_opus_restriction(connections, provider, family):
    path, original = connections
    document = copy.deepcopy(original)
    model = document[provider]["models"]["claude"]
    model.pop("model_family")
    if family:
        model["model_family"] = family
    path.write_text(yaml.safe_dump(document))
    run = profiles.resolve_scan(provider)
    cli._engine_imports()
    if family == "non-opus":
        profiles.apply_runtime_profile(run, {"opus_disabled": True}, [])
    else:
        with pytest.raises(profiles.ProfileError, match="Opus"):
            profiles.apply_runtime_profile(run, {"opus_disabled": True}, [])


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
def test_provider_controller_publishes_with_selected_role_models(connections, tmp_path, monkeypatch, provider):
    from orchestrator import orchestration_controller as controller
    from runtime import multi_repo_scope

    from tests.test_multi_repo_assessment import FullHost
    from tests.test_multi_repo_controller import checkout

    run = profiles.resolve_scan(provider, depth="quick")
    root, output = tmp_path / "app", tmp_path / "out"
    checkout(root)
    host = FullHost()
    real_admit = multi_repo_scope.admit

    def admit(*args, **kwargs):
        host.scope = real_admit(*args, **kwargs)
        return host.scope

    monkeypatch.setattr(multi_repo_scope, "admit", admit)
    dispatched = {}

    def factory(role, model, ceiling):
        dispatched[role] = model
        return host.factory(role, model, ceiling)

    result = controller.assess_repositories(
        [
            "--repo",
            str(root),
            "--output",
            str(output),
            "--hard-budget",
            "20",
            "--assessment-depth",
            "quick",
            "--trust-mode",
            "trusted",
        ],
        host_factory=factory,
        progress=lambda text: None,
        run_profile=run,
    )
    assert result["status"] == "complete"
    expected = run["models"]["stride_analyzer"]["model"]
    assert dispatched["stride_analyzer"] == expected and dispatched["recon_scanner"] == expected
    state = json.loads((output / ".assessment-state.json").read_text())
    assert state["operator_profile"]["adapter"] == provider
    model = yaml.safe_load((output / "security-assessment.yaml").read_text())
    assert model["meta"]["model_configuration"]["stride_analyzer"]["model"] == expected


def test_capabilities_show_provider_availability_without_live_qualification(capsys):
    assert cli.main(["capabilities"]) == 0
    providers = json.loads(capsys.readouterr().out)["assessment"]["providers"]
    assert providers["lite"]["adapter"] == "responses" and providers["lite"]["qualified"] is False
    assert providers["bedrock"]["adapter"] == "converse" and providers["bedrock"]["qualified"] is False


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
def test_startup_discloses_provider_destination(connections, provider, tmp_path):
    from orchestrator import orchestration_controller as controller
    from runtime.assessment_jobs import AssessmentBudget

    run = profiles.resolve_scan(provider)
    ns, _ = controller._assessment_argument_parser().parse_known_args(
        [
            "--repo",
            str(tmp_path / "repo"),
            "--output",
            str(tmp_path / "out"),
            "--hard-budget",
            "20",
        ]
    )
    settings = run["models"]["stride_analyzer"]
    cfg = {"operator_profile": run, "host_profile": {"kind": provider, "endpoint": settings["endpoint"]}}
    rows = dict(
        controller._assessment_intro(ns, AssessmentBudget(20, 2, 100, 600), "standard", "models", "stages", cfg=cfg)
    )
    assert settings["endpoint"] in rows["Model host"]
    assert "excerpts, context and answers leave" in rows["Model host"]
    lineup, _ = controller._assessment_model_lines(cfg)
    assert f"{provider} claude" in lineup


@pytest.mark.parametrize(
    "body",
    [
        "schema_version: 1\nschema_version: 2\n",
        "schema_version: !!python/object/apply:os.system ['false']\n",
        "schema_version: 1\nlite: &x {models: *x}\n",
        "[]\n",
    ],
)
def test_ambiguous_or_executable_connection_yaml_is_rejected(connections, body):
    connections[0].write_text(body)
    with pytest.raises(profiles.ProfileError):
        profiles.resolve_scan("lite")


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
@pytest.mark.parametrize(
    "address", ["127.0.0.1", "169.254.169.254", "10.0.0.1", "::1", "fe80::1", "224.0.0.1", "ff02::1"]
)
def test_provider_dns_cannot_reach_internal_or_metadata_destinations(connections, provider, address, monkeypatch):
    import socket

    selected = profiles.api_profile(profiles.resolve_scan(provider)["models"]["stride_analyzer"])
    monkeypatch.setenv(selected.key_env, "artificial-test-token")
    monkeypatch.setattr(api_hosts.socket, "getaddrinfo", lambda *a, **kw: [(socket.AF_INET, 1, 6, "", (address, 443))])
    monkeypatch.setattr(api_hosts, "_PinnedHTTPS", lambda *a, **kw: pytest.fail("no connection permitted"))
    with pytest.raises(api_hosts.ApiTransportError, match="destination_denied"):
        api_hosts.ResponsesTransport(selected, 2).invoke("system", "source", {}, 3, lambda: False)


def test_gateway_private_destination_requires_explicit_pin(connections, wire):
    path, document = connections
    document["lite"]["pinned_ip"] = "10.4.5.6"
    path.write_text(yaml.safe_dump(document))
    assert invoke("lite", wire).payload == {"accepted": True}
    assert wire[0].instances[0].address == "10.4.5.6"


@pytest.mark.parametrize("provider", ["lite", "bedrock"])
def test_provider_budget_and_cancellation_stop_before_transmission(connections, wire, provider):
    from runtime.analyst_host import HostCancelled

    selected = profiles.api_profile(profiles.resolve_scan(provider)["models"]["stride_analyzer"])
    with pytest.raises(api_hosts.ApiTransportError, match="budget_exhausted"):
        api_hosts.ResponsesTransport(selected, 0.00001).invoke("system", "source", {}, 3, lambda: False)
    with pytest.raises(HostCancelled):
        api_hosts.ResponsesTransport(selected, 2).invoke("system", "source", {}, 3, lambda: True)
    assert wire[0].instances == []


def test_duplicate_json_cannot_supply_an_ambiguous_gateway_answer(connections, wire):
    wire[0].response = _response({"accepted": True}).replace(
        b'"status": "completed"', b'"status": "failed", "status": "completed"'
    )
    with pytest.raises(api_hosts.ApiTransportError, match="invalid_response"):
        invoke("lite", wire)


def test_nonfinite_gateway_payload_is_rejected(connections, wire):
    wire[0].response = _response({"number": float("inf")}).replace(b"Infinity", b"1e999")
    with pytest.raises(api_hosts.ApiTransportError, match="invalid_response"):
        invoke("lite", wire)


def test_conflicting_cli_model_cannot_be_silently_ignored(connections, monkeypatch, tmp_path):
    cli._engine_imports()
    from runtime import remote_repositories

    home = connections[0].parent
    (home / "profiles").mkdir()
    (home / "profiles/custom.yaml").write_text("schema_version: 1\nmodel_profile: lite\n")
    monkeypatch.setattr(remote_repositories, "checkout_arguments", lambda *a: pytest.fail("no checkout"))
    assert cli.main(["assess", "--profile", "custom", "--model", "unrelated-model"]) == 2


@pytest.mark.parametrize("mode", [0o666, 0o664])
def test_other_users_cannot_write_provider_connection(connections, mode):
    connections[0].chmod(mode)
    with pytest.raises(profiles.ProfileError, match="not writable"):
        profiles.resolve_scan("lite")
