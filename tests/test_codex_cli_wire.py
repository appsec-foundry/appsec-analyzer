"""Explicit local wire qualification of the real CLI, never an OpenAI call.

Run with APPSEC_CODEX_OFFLINE_QUALIFICATION=1. The CLI receives only an artificial
API key and a loopback Responses fixture. No existing login or source is used.
"""

from __future__ import annotations

import http.server
import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

import pytest

from appsec_analyzer import codex_cli

pytestmark = pytest.mark.skipif(
    os.environ.get("APPSEC_CODEX_OFFLINE_QUALIFICATION") != "1", reason="explicit local CLI wire qualification"
)


@pytest.mark.parametrize(
    "success,commentary,reconnect,failure_mode",
    [
        (False, False, False, None),
        (True, False, False, None),
        (True, True, False, None),
        (True, False, True, None),
        (False, False, False, "server_error"),
        (False, False, False, "stream_disconnected"),
        (False, False, False, "connection_timeout"),
    ],
)
def test_real_codex_has_no_tools_and_ignores_project_and_user_configuration(
    tmp_path, monkeypatch, success, commentary, reconnect, failure_mode
):
    executable = shutil.which("codex")
    assert executable
    env = {
        "PATH": os.environ["PATH"],
        "HOME": str(tmp_path),
        "CODEX_HOME": str(tmp_path / "codex-home"),
        "FIXTURE_KEY": "artificial-offline-key",
    }
    home = Path(env["CODEX_HOME"])
    home.mkdir()
    marker = tmp_path / "unexpected-execution"
    # Loading this configuration would launch a server before inference.
    (home / "config.toml").write_text(
        '[mcp_servers.forbidden]\ncommand="touch"\nargs=[' + json.dumps(str(marker)) + "]\n"
    )
    (tmp_path / "AGENTS.md").write_text("FORBIDDEN_PROJECT_INSTRUCTION\n")
    version = subprocess.run([executable, "--version"], env=env, capture_output=True, text=True, check=True)
    codex_cli.compatible_version(version.stdout.encode())
    features = subprocess.run([executable, "features", "list"], env=env, capture_output=True, text=True, check=True)
    disabled = {
        parts[0]: False
        for line in features.stdout.splitlines()
        if (parts := line.split())[1] not in ("removed", "deprecated")
    }
    disabled["skip_host_skill_discovery"] = True
    requests = []
    release = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            if (reconnect and len(requests) == 1) or failure_mode in ("stream_disconnected", "connection_timeout"):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.end_headers()
                if failure_mode == "connection_timeout":
                    self.wfile.write(b": synthetic keepalive\n\n")
                    self.wfile.flush()
                    release.wait(5)
                return
            if not success:
                self.send_response(503 if failure_mode == "server_error" else 400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                message = "service unavailable" if failure_mode == "server_error" else "offline fixture completed"
                self.wfile.write(json.dumps({"error": {"message": message, "type": "invalid_request_error"}}).encode())
                return
            text = json.dumps({"payload": {"ok": True}})
            part = {"type": "output_text", "text": text, "annotations": []}
            message = {
                "id": "msg_fixture",
                "type": "message",
                "role": "assistant",
                "phase": "final_answer",
                "status": "completed",
                "content": [part],
            }
            response = {
                "id": "resp_fixture",
                "object": "response",
                "created_at": 1,
                "status": "completed",
                "model": "gpt-6.1-sol",
                "output": [message],
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 10,
                    "total_tokens": 20,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens_details": {"reasoning_tokens": 0},
                },
            }
            sequence = [
                {"type": "response.created", "response": {**response, "status": "in_progress", "output": []}},
                {
                    "type": "response.output_item.added",
                    "output_index": 0,
                    "item": {**message, "status": "in_progress", "content": []},
                },
                {
                    "type": "response.content_part.added",
                    "output_index": 0,
                    "item_id": "msg_fixture",
                    "content_index": 0,
                    "part": {**part, "text": ""},
                },
                {
                    "type": "response.output_text.delta",
                    "output_index": 0,
                    "item_id": "msg_fixture",
                    "content_index": 0,
                    "delta": text,
                },
                {
                    "type": "response.output_text.done",
                    "output_index": 0,
                    "item_id": "msg_fixture",
                    "content_index": 0,
                    "text": text,
                },
                {
                    "type": "response.content_part.done",
                    "output_index": 0,
                    "item_id": "msg_fixture",
                    "content_index": 0,
                    "part": part,
                },
                {"type": "response.output_item.done", "output_index": 0, "item": message},
                {"type": "response.completed", "response": response},
            ]
            if commentary:
                progress = {
                    **message,
                    "id": "msg_commentary",
                    "phase": "commentary",
                    "content": [{**part, "text": "I will prepare the structured answer."}],
                }
                response["output"] = [progress, message]
                for event in sequence:
                    if "output_index" in event:
                        event["output_index"] = 1
                sequence[1:1] = [
                    {
                        "type": "response.output_item.added",
                        "output_index": 0,
                        "item": {**progress, "status": "in_progress", "content": []},
                    },
                    {
                        "type": "response.output_text.delta",
                        "output_index": 0,
                        "item_id": "msg_commentary",
                        "content_index": 0,
                        "delta": progress["content"][0]["text"],
                    },
                    {"type": "response.output_item.done", "output_index": 0, "item": progress},
                ]
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for event in sequence:
                self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())

        def log_message(self, *args):
            pass

    with http.server.HTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            transport = codex_cli.CodexCliTransport(
                tmp_path, "gpt-6.1-sol", "medium", {"executable": executable, "features": disabled}
            )
            original_argv = transport.argv

            def argv(schema, instructions):
                command = [
                    arg.replace('forced_login_method="chatgpt"', 'forced_login_method="api"').replace(
                        "model_providers.appsec_chatgpt.requires_openai_auth=true",
                        "model_providers.appsec_chatgpt.requires_openai_auth=false",
                    )
                    for arg in original_argv(schema, instructions)
                ]
                command[-1:-1] = [
                    "-c",
                    f'model_providers.appsec_chatgpt.base_url="http://127.0.0.1:{server.server_port}/v1"',
                    "-c",
                    'model_providers.appsec_chatgpt.env_key="FIXTURE_KEY"',
                ]
                if reconnect:
                    # Exercise recovery semantics even though production disables stream retries.
                    command[-1:-1] = ["-c", "model_providers.appsec_chatgpt.stream_max_retries=1"]
                if failure_mode == "connection_timeout":
                    # Shorten only the fixture's idle clock; retain production retry settings.
                    command[-1:-1] = ["-c", "model_providers.appsec_chatgpt.stream_idle_timeout_ms=100"]
                return command

            # Only this local fixture replaces provider/auth, never production.
            monkeypatch.setattr(transport, "argv", argv)
            monkeypatch.setattr(codex_cli, "environment", lambda: env)
            original_run = codex_cli._run
            observed_events = []

            def observed_run(*args, **kwargs):
                result = original_run(*args, **kwargs)
                observed_events.extend(json.loads(line) for line in result[1].splitlines())
                return result

            monkeypatch.setattr(codex_cli, "_run", observed_run)
            if success:
                result = transport.invoke(
                    "Return the requested JSON without tools.",
                    "Return JSON.",
                    {
                        "type": "object",
                        "properties": {"ok": {"type": "boolean"}},
                        "required": ["ok"],
                        "additionalProperties": False,
                    },
                    20,
                    lambda: False,
                )
                assert result.payload == {"ok": True} and result.usd is None
                messages = [
                    event["item"]
                    for event in observed_events
                    if event.get("type") == "item.completed" and event["item"].get("type") == "agent_message"
                ]
                assert len(messages) == (2 if commentary else 1)
            else:
                from runtime.analyst_host import TransportError

                with pytest.raises(TransportError) as caught:
                    transport.invoke("Return JSON.", "Return JSON.", {}, 20, lambda: False)
                if failure_mode:
                    assert caught.value.reason == failure_mode
        finally:
            release.set()
            server.shutdown()
            thread.join(timeout=2)
    assert len(requests) == (2 if reconnect else 1)
    assert requests[0].get("tools", []) == []
    output_schema = requests[0]["text"]["format"]["schema"]
    assert set(output_schema["properties"]) == {"payload"}
    assert "payload_json" not in json.dumps(output_schema)
    if success:
        from jsonschema import Draft202012Validator

        Draft202012Validator(output_schema).validate({"payload": {"ok": True}})
        assert not Draft202012Validator(output_schema).is_valid({"payload": '{"ok":true}'})
    assert "FORBIDDEN_PROJECT_INSTRUCTION" not in json.dumps(requests)
    assert not marker.exists()
