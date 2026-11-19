"""Offline checks of user data at the managed model boundary."""

import json

import pytest
from runtime import assessment_host as host
from runtime.analyst_host import HostReply
from runtime.model_secrets import ModelSecretError, ModelSecrets
from runtime.multi_repo_scope import AssessmentScope, RepositoryView

RID = "repo-0123456789abcdef"
SCHEMA = {"type": "object", "properties": {"summary": {"type": "string"}}, "required": ["summary"]}


class RecordingHost:
    def __init__(self, *summaries):
        self.requests = []
        self.summaries = iter(summaries)

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        self.requests.append((system, prompt, schema))
        return HostReply({"action": "complete", "reads": [], "artifact": {"summary": next(self.summaries)}}, 0.01)


def exchange(tmp_path, transport, *, files=None, **changes):
    repo = RepositoryView(RID, tmp_path, "a" * 40, "b" * 64, files or {})
    options = dict(
        instructions="Review the supplied material.",
        context={},
        artifact_schema=SCHEMA,
        allowed_sources=frozenset((RID, path) for path in repo.files),
        timeout_s=30,
        should_stop=lambda: False,
    )
    return host.run_exchange(transport, AssessmentScope((repo,), tmp_path / "out"), **(options | changes))


def test_model_handoff_masks_source_repeats_and_corrections(tmp_path, monkeypatch):
    credential = "fixture1:with spaces & punctuation"
    configured = "offline-provider-example"
    token = "glpat-" + "x" * 22
    monkeypatch.setenv("OPENAI_API_KEY", configured)
    files = {"a.txt": credential.encode(), "z.py": f'password = "{credential}"'.encode()}
    transport = RecordingHost(f"draft {token}", "accepted")

    def review(artifact, slices):
        if artifact["summary"].startswith("draft"):
            raise ValueError("Please correct this draft.")

    result = exchange(
        tmp_path,
        transport,
        files=files,
        preload=[(RID, p, 1, 1) for p in files],
        context={"note": f"{credential} and {configured}"},
        review=review,
    )
    assert result.calls == len(transport.requests) == 2
    for system, prompt, schema in transport.requests:
        assert str(prompt) == "".join(prompt.blocks)
        message = json.dumps([system, prompt.blocks, schema])
        assert all(value not in message for value in (configured, token, credential, "with spaces & punctuation"))
        assert "[REDACTED]" in prompt
    assert "rejected_result" in transport.requests[1][1]


@pytest.mark.parametrize("location", ["instructions", "schema", "key"])
def test_uncheckable_contract_withholds_the_call_without_echoing_values(tmp_path, location):
    synthetic = "sk-proj-" + "s" * 30
    changes = {
        "instructions": {"instructions": synthetic},
        "schema": {"artifact_schema": dict(SCHEMA, description=synthetic)},
        "key": {"context": {synthetic: "hello"}},
    }
    transport = RecordingHost()
    with pytest.raises(ModelSecretError) as exc:
        exchange(tmp_path, transport, **changes[location])
    assert transport.requests == [] and synthetic not in str(exc.value)


def test_secret_limit_and_structured_escaped_values_fail_closed(monkeypatch):
    guard = ModelSecrets()
    secret = 'fixture "quoted" value'
    assert guard.protect({"note": secret, "nested": {"api_key": secret}}) == {
        "note": "[REDACTED]",
        "nested": {"api_key": "[REDACTED]"},
    }
    monkeypatch.setattr("runtime.model_secrets.MAX_VALUES", 1)
    with pytest.raises(ModelSecretError):
        guard.protect({"password": "another fixture"})
    with pytest.raises(ModelSecretError):
        guard.require_clean("another fixture")


def test_each_role_remembers_values_seen_by_an_earlier_role(tmp_path):
    synthetic = "offline-cross-role-example"
    scope = AssessmentScope((), tmp_path)
    first = RecordingHost("accepted")
    second = RecordingHost("accepted")
    options = dict(
        instructions="review",
        artifact_schema=SCHEMA,
        allowed_sources=frozenset(),
        timeout_s=10,
        should_stop=lambda: False,
    )
    host.run_exchange(first, scope, context={"settings": {"password": synthetic}}, **options)
    host.run_exchange(second, scope, context={"unlabelled": synthetic}, **options)
    assert all(synthetic not in transport.requests[0][1] for transport in (first, second))
    assert "[REDACTED]" in second.requests[0][1]


def test_bare_copy_of_a_pem_body_is_withheld_from_model_input():
    line = "MIIB" + "7" * 56
    private = "-----BEGIN PRIVATE KEY-----\n" + line + "\n-----END PRIVATE KEY-----"
    packet = ModelSecrets().protect({"source": private, "copy": line})
    assert line not in json.dumps(packet)


def test_authorization_headers_and_url_credentials_are_removed_with_their_repeats():
    opaque = "offline-header-example"
    guard = ModelSecrets()
    packet = guard.protect(
        {
            "headers": {"Authorization": f"Bearer {opaque}"},
            "note": opaque,
            "url": "https://reader:offline%23example@example.invalid/",
            "repeat": "offline#example",
        }
    )
    assert packet["note"] == packet["repeat"] == "[REDACTED]"
    assert "offline" not in json.dumps(packet)


def test_escaped_known_value_in_serialized_input_stops_before_transmission():
    with pytest.raises(ModelSecretError):
        ModelSecrets(["fixture123"]).protect(r'{"note":"fixture\u003123"}')


def test_unquoted_assignment_keeps_no_reusable_suffix():
    value = "fixture123:rest&more"
    packet = ModelSecrets().protect({"first": value, "config": "db_password=" + value})
    assert value not in json.dumps(packet) and "rest&more" not in json.dumps(packet)


@pytest.mark.parametrize("backend", ["codex", "copilot"])
def test_subscription_cli_receives_only_the_checked_prompt(tmp_path, monkeypatch, backend):
    from pathlib import Path

    from appsec_analyzer import codex_cli, copilot_cli

    synthetic = "offline-subscription-secret"
    monkeypatch.setenv("GH_TOKEN", synthetic)
    module, adapter = (
        (codex_cli, codex_cli.CodexCliTransport)
        if backend == "codex"
        else (copilot_cli, copilot_cli.CopilotCliTransport)
    )
    runtime = {"executable": "offline", "features": {}}
    transport = adapter(tmp_path, "fixture-model", "medium", runtime)
    sent = []

    def capture(argv, *, data, cwd, **kwargs):
        material = [data, json.dumps(argv).encode()]
        material.extend(p.read_bytes() for p in Path(cwd).iterdir() if p.is_file())
        sent.extend(material)
        raise StopIteration("captured before process launch")

    monkeypatch.setattr(module, "_run", capture)
    with pytest.raises(StopIteration, match="captured"):
        exchange(tmp_path, transport, context={"note": synthetic})
    assert b"[REDACTED]" in sent[0]
    assert all(synthetic.encode() not in item for item in sent)


def test_claude_cache_blocks_reach_the_cli_without_secrets(tmp_path, monkeypatch):
    from runtime.analyst_host import ClaudeCliTransport

    from tests.test_analyst_host import fake_host, log

    synthetic = "offline-claude-example"
    monkeypatch.setenv("ANTHROPIC_API_KEY", synthetic)
    reply = {
        "type": "result",
        "is_error": False,
        "total_cost_usd": 0.01,
        "structured_output": {"action": "complete", "reads": [], "artifact": {"summary": "checked"}},
    }
    executable = fake_host(tmp_path, f"print(json.dumps({reply!r}))\n")
    adapter = ClaudeCliTransport(tmp_path / "work", executable=executable, cache_blocks=True)
    exchange(tmp_path, adapter, context={"note": synthetic}, shared_context_keys=1)
    record = log(tmp_path)
    assert synthetic not in json.dumps(record)
    blocks = json.loads(record["prompt"])["message"]["content"]
    assert any("[REDACTED]" in block["text"] for block in blocks)
