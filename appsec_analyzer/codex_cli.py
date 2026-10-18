"""Bounded, isolated Codex CLI exchanges using its managed ChatGPT login.

Only the reviewed CLI version is admitted: its tool configuration is checked
against a synthetic local Responses endpoint by the offline qualification test.
No credential file is read or copied by Analyzer.
"""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from jsonschema.exceptions import SchemaError

from appsec_analyzer import resource_root

_scripts = str(resource_root() / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from runtime.analyst_host import HostCancelled, HostReply, HostTimeout, TransportError

from appsec_analyzer.codex_schema import CodexSchema

SUPPORTED_VERSION = "0.163.0"
MAX_BYTES = 1_048_576
# The prompt goes through stdin, instructions and schema through files. The
# bound leaves a STRIDE packet the shared MAX_CONTEXT_BYTES after the role
# instructions and the larger native output schema, as other hosts receive.
MAX_REQUEST_BYTES = 320_000
# One stateless exchange: do not let the CLI silently replay it outside the
# controller's call accounting. Bound the wait for incoming SSE events.
STREAM_IDLE_TIMEOUT_MS = 60_000


def _instructions(system):
    return (
        system + "\nReturn one JSON object matching the output schema, with your response as structured payload. "
        "Do not serialize the response document into a string; source quotations remain strings. Optional canonical fields use presence wrappers: "
        '{"present":false} means absent; {"present":true,"value":...} means present, including explicit null. '
        "Dynamic object members use key/value entry arrays in __extra fields; unconstrained JSON objects "
        "use an entries wrapper. These are wire representations only; follow the trusted task for the canonical result."
    )


def prompt_capacity(system, schema):
    """Prompt bytes left after the same instructions invoke will actually send."""
    wire = CodexSchema(schema)
    return max(
        0,
        MAX_REQUEST_BYTES
        - len(_instructions(system).encode("utf-8"))
        - len(json.dumps(wire.schema, separators=(",", ":")).encode("utf-8")),
    )


def _json(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ambiguous JSON")
            result[key] = value
        return result

    def invalid_constant(value):
        raise ValueError("non-finite JSON")

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON")
        return number

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant, parse_float=finite)


def _stop(proc):
    # The group can outlive its parent. Always stop it, including when the
    # parent exited before the output reader observed cancellation or EOF.
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        if sig == signal.SIGTERM:
            time.sleep(0.1)
    proc.wait(timeout=5)


def environment() -> dict[str, str]:
    # In particular, drop API keys, endpoint overrides, proxy credentials,
    # inherited Codex sessions and all repository-selected configuration.
    allowed = (
        "PATH",
        "HOME",
        "CODEX_HOME",
        "XDG_CONFIG_HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "SYSTEMROOT",
        "LANG",
    )
    return {key: os.environ[key] for key in allowed if key in os.environ}


def _reconnect(event):
    if event.get("type") != "error" or type(event.get("message")) is not str:
        return None
    match = re.match(r"^Reconnecting\.\.\. ([0-9]{1,2})/([0-9]{1,2})(?: \(|$)", event["message"])
    if match and 1 <= int(match[1]) <= int(match[2]) <= 99:
        return int(match[1]), int(match[2])
    return None


def _failure(failures, stderr, code):
    """Classify CLI error events as well as stderr; return no provider prose."""
    text = (json.dumps(failures) + " " + stderr[-16384:].decode("utf-8", errors="replace")).lower()
    rules = (
        ("quota_exhausted", ("usage_limit", "usage limit", "quota")),
        ("rate_limit", ("rate_limit", "rate limit", "429")),
        ("authentication_failed", ("unauthorized", "authentication", "401", "403")),
        ("host_configuration", ("error loading config", "reserved built-in provider")),
        ("model_unavailable", ("model_not_found", "model not found", "not supported", "does not exist")),
        ("tls_error", ("certificate", "tls handshake")),
        ("connection_timeout", ("timed out", "timeout")),
        ("stream_disconnected", ("stream disconnected", "stream closed", "connection closed")),
        ("connection_failed", ("error sending request", "failed to connect", "connection reset", "dns error")),
        ("server_error", ("internal server error", "service unavailable", "bad gateway")),
        ("invalid_request", ("invalid_request", "invalid schema")),
    )
    reason = next((reason for reason, markers in rules if any(marker in text for marker in markers)), None)
    if reason is None:
        from runtime.analyst_host import _stderr_failure

        reason, _ = _stderr_failure(text.encode())
        if reason == "no_result":
            reason = "transport"
    from runtime.assessment_diagnostics import transport_summary

    error = TransportError("Codex CLI exchange failed", reason=reason, exit_code=code)
    error.args = ("Codex CLI exchange failed: " + transport_summary(error),)
    return error


def _activity(line, on_event):
    """Forward only fixed status values and counts, never model-controlled text."""
    try:
        event = _json(line)
        if type(event) is not dict:
            return
        if reconnect := _reconnect(event):
            on_event({"type": "host_activity", "phase": "reconnecting", "attempt": reconnect[0], "limit": reconnect[1]})
            return
        if event.get("type") not in ("item.started", "item.updated", "item.completed"):
            return
        item = event.get("item")
        if type(item) is not dict:
            return
        if item.get("type") == "reasoning":
            status = {"type": "host_activity", "phase": "thinking"}
        elif item.get("type") == "agent_message":
            text = item.get("text", "")
            if type(text) is not str:
                return
            status = {"type": "host_activity", "phase": "writing", "characters": len(text)}
        else:
            return
        on_event(status)
    except Exception:
        # Telemetry is optional; final response validation remains authoritative.
        pass


def _run(argv, *, cwd, env, data=b"", timeout_s=10, should_stop=lambda: False, on_event=None):
    if should_stop():
        raise HostCancelled("Codex call cancelled before transmission")
    try:
        proc = subprocess.Popen(
            argv,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError:
        raise TransportError("Codex CLI could not be started", reason="host_unavailable") from None
    # Feed large prompts independently so pipe backpressure cannot block cancellation.
    import threading

    from runtime.analyst_host import _feed

    threading.Thread(target=_feed, args=(proc.stdin, data), daemon=True).start()
    streams = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    activity_cursor = 0
    deadline = time.monotonic() + timeout_s
    try:
        with selectors.DefaultSelector() as selected:
            for pipe in streams:
                selected.register(pipe, selectors.EVENT_READ)
            while selected.get_map():
                if should_stop():
                    raise HostCancelled("Codex call cancelled")
                if time.monotonic() >= deadline:
                    raise HostTimeout("Codex call exceeded its time limit")
                for key, _ in selected.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        if key.fileobj is proc.stdout and on_event:
                            _activity(bytes(streams[proc.stdout][activity_cursor:]), on_event)
                        continue
                    streams[key.fileobj].extend(chunk)
                    if sum(map(len, streams.values())) > MAX_BYTES:
                        raise TransportError("Codex output exceeds its size limit", reason="response_too_large")
                    if key.fileobj is proc.stdout and on_event:
                        output = streams[proc.stdout]
                        while (end := output.find(b"\n", activity_cursor)) >= 0:
                            _activity(bytes(output[activity_cursor:end]), on_event)
                            activity_cursor = end + 1
            while proc.poll() is None:
                if should_stop():
                    raise HostCancelled("Codex call cancelled")
                if time.monotonic() >= deadline:
                    raise HostTimeout("Codex call exceeded its time limit")
                time.sleep(0.05)
        return proc.returncode, bytes(streams[proc.stdout]), bytes(streams[proc.stderr])
    finally:
        _stop(proc)
        for pipe in (proc.stdout, proc.stderr):
            pipe.close()


def preflight(*, repositories=()) -> dict:
    try:
        return _preflight(repositories=repositories)
    except (TransportError, HostTimeout):
        raise ValueError(
            "Codex CLI preflight failed; check codex --version and codex login status, then retry"
        ) from None


def _preflight(*, repositories=()) -> dict:
    executable = shutil.which("codex")
    if executable is None or os.name != "posix":
        raise ValueError("codex-cli requires Codex CLI 0.163.0 on Linux or macOS; see docs/profiles.md")
    executable = str(Path(executable).resolve())
    from appsec_analyzer.profiles import ProfileError, reject_source_paths

    try:
        reject_source_paths([executable], repositories)
    except ProfileError:
        raise ValueError("Codex CLI executable must be outside the analyzed repositories") from None
    env = environment()
    with tempfile.TemporaryDirectory(prefix="appsec-codex-check-") as work:
        code, out, _ = _run([executable, "--version"], cwd=work, env=env)
        if code or out.strip() != f"codex-cli {SUPPORTED_VERSION}".encode():
            raise ValueError("codex-cli requires reviewed Codex CLI version 0.163.0")
        code, out, _ = _run([executable, "features", "list"], cwd=work, env=env)
        if code:
            raise ValueError("Codex CLI feature configuration is unavailable")
        features = {}
        for line in out.decode("utf-8", errors="strict").splitlines():
            parts = line.split()
            if len(parts) < 3 or not re.fullmatch(r"[a-z0-9_.]+", parts[0]) or parts[-1] not in ("true", "false"):
                raise ValueError("Codex CLI feature configuration is invalid")
            if parts[1] not in ("removed", "deprecated"):
                features[parts[0]] = False
        if (
            not {"shell_tool", "hooks", "apps", "plugins", "multi_agent", "skip_host_skill_discovery"}
            <= features.keys()
        ):
            raise ValueError("Codex CLI isolation features are unavailable")
        features["skip_host_skill_discovery"] = True
        code, out, err = _run([executable, "-c", 'forced_login_method="chatgpt"', "login", "status"], cwd=work, env=env)
        if code or b"Logged in using ChatGPT" not in (out + err).splitlines():
            raise ValueError("Codex CLI needs a ChatGPT login; run codex login before starting Analyzer")
    return {"executable": executable, "version": SUPPORTED_VERSION, "features": features}


class CodexCliTransport:
    def __init__(self, work_root: Path, model: str, effort: str, runtime: dict):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", model):
            raise ValueError("invalid Codex model")
        if effort not in ("none", "low", "medium", "high", "xhigh", "max"):
            raise ValueError("invalid Codex reasoning effort")
        self.work_root, self.model, self.effort, self.runtime = work_root, model, effort, runtime
        self.on_event = None

    def argv(self, schema_path: Path, instructions_path: Path) -> list[str]:
        features = (
            "{" + ",".join(json.dumps(k) + "=" + str(v).lower() for k, v in self.runtime["features"].items()) + "}"
        )
        config = {
            "features": features,
            # Built-in IDs are reserved in 0.163.0. A dedicated definition
            # retains Codex-managed OpenAI auth and its default ChatGPT route.
            "model_provider": '"appsec_chatgpt"',
            "forced_login_method": '"chatgpt"',
            "approval_policy": '"never"',
            "web_search": '"disabled"',
            "mcp_servers": "{}",
            "project_doc_max_bytes": "0",
            "history.persistence": '"none"',
            "model_reasoning_effort": json.dumps(self.effort),
            "model_instructions_file": json.dumps(str(instructions_path)),
            "model_providers.appsec_chatgpt.name": '"OpenAI"',
            "model_providers.appsec_chatgpt.requires_openai_auth": "true",
            "model_providers.appsec_chatgpt.wire_api": '"responses"',
            "model_providers.appsec_chatgpt.supports_websockets": "false",
            "model_providers.appsec_chatgpt.request_max_retries": "0",
            "model_providers.appsec_chatgpt.stream_max_retries": "0",
            "model_providers.appsec_chatgpt.stream_idle_timeout_ms": str(STREAM_IDLE_TIMEOUT_MS),
        }
        return [
            self.runtime["executable"],
            "exec",
            "--ignore-user-config",
            "--ignore-rules",
            "--strict-config",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox",
            "read-only",
            "--json",
            "--color",
            "never",
            "--model",
            self.model,
            "--output-schema",
            str(schema_path),
            *[arg for key, value in config.items() for arg in ("-c", key + "=" + value)],
            "-",
        ]

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        if type(system) is not str or type(prompt) is not str or type(schema) is not dict:
            raise TransportError("Invalid Codex request", reason="invalid_request")
        if type(timeout_s) is not int or not 1 <= timeout_s <= 3600:
            raise TransportError("Invalid Codex timeout", reason="invalid_request")
        try:
            wire_schema = CodexSchema(schema)
        except (ValueError, KeyError, TypeError, IndexError, RecursionError, SchemaError):
            raise TransportError("Unsupported Codex output contract", reason="invalid_request") from None
        instructions = _instructions(system)
        data = prompt.encode("utf-8")
        encoded_schema = json.dumps(wire_schema.schema, separators=(",", ":"))
        if len(instructions.encode("utf-8")) + len(data) + len(encoded_schema.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise TransportError("Codex request exceeds its size limit", reason="request_too_large")
        with tempfile.TemporaryDirectory(prefix="codex-", dir=self.work_root) as work:
            root = Path(work)
            schema_path, instructions_path = root / "schema.json", root / "instructions.txt"
            schema_path.write_text(encoded_schema, encoding="utf-8")
            instructions_path.write_text(instructions, encoding="utf-8")
            schema_path.chmod(0o600)
            instructions_path.chmod(0o600)
            code, out, err = _run(
                self.argv(schema_path, instructions_path),
                cwd=work,
                env=environment(),
                data=data,
                timeout_s=timeout_s,
                should_stop=should_stop,
                on_event=self.on_event,
            )
        response_reason = "invalid_response_stream"
        try:
            events = [_json(line) for line in out.splitlines() if line]
            if any(type(event) is not dict for event in events):
                raise ValueError
            # Codex emits recoverable reconnect notices as top-level errors.
            # A successful terminal turn may follow them. Unknown errors and
            # turn.failed remain fatal, even if an answer appears afterwards.
            failures = [
                e for e in events if e.get("type") == "turn.failed" or (e.get("type") == "error" and not _reconnect(e))
            ]
            if code or failures:
                errors = [e for e in events if e.get("type") in ("turn.failed", "error")]
                raise _failure(errors, err, code)
            completed = [e for e in events if e.get("type") == "turn.completed"]
            messages = []
            response_reason = "unexpected_host_item"
            for event in events:
                if event.get("type") not in ("item.started", "item.updated", "item.completed"):
                    continue
                item = event.get("item")
                # CLI startup warnings also use error items. A failed turn is
                # signalled by turn.failed/error above, not this item type.
                if type(item) is not dict or item.get("type") not in ("agent_message", "reasoning", "error"):
                    raise ValueError("unexpected tool event")
                if event["type"] == "item.completed" and item["type"] == "agent_message":
                    if type(item.get("text")) is not str:
                        raise ValueError
                    messages.append(item["text"])
            response_reason = "incomplete_response"
            if len(completed) != 1 or not messages or events[-1].get("type") != "turn.completed":
                raise ValueError
            # Codex can emit commentary before its final structured message.
            # Only the last completed agent message is the answer; never fall
            # back to an earlier valid object when the final message is invalid.
            response_reason = "invalid_response_envelope"
            wire = _json(messages[-1])
            if type(wire) is not dict or set(wire) != {"payload"}:
                raise ValueError
            response_reason = "invalid_response_payload"
            payload = wire_schema.decode(wire)
        except (ValueError, KeyError, TypeError, UnicodeError, RecursionError):
            raise TransportError(
                "Invalid Codex structured response: " + response_reason, reason=response_reason, exit_code=code
            ) from None
        return HostReply(payload=payload, usd=None)
