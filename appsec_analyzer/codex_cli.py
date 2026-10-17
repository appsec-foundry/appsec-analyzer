"""Bounded, isolated Codex CLI exchanges using its managed ChatGPT login.

Only the reviewed CLI version is admitted: its tool configuration is checked
against a synthetic local Responses endpoint by the offline qualification test.
No credential file is read or copied by Analyzer.
"""

from __future__ import annotations

import json
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

from appsec_analyzer import resource_root

_scripts = str(resource_root() / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from runtime.analyst_host import HostCancelled, HostReply, HostTimeout, TransportError

from appsec_analyzer.api_hosts import _WIRE_SCHEMA

SUPPORTED_VERSION = "0.163.0"
MAX_BYTES = 1_048_576
MAX_REQUEST_BYTES = 240_000


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

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


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


def _run(argv, *, cwd, env, data=b"", timeout_s=10, should_stop=lambda: False):
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
                        continue
                    streams[key.fileobj].extend(chunk)
                    if sum(map(len, streams.values())) > MAX_BYTES:
                        raise TransportError("Codex output exceeds its size limit", reason="response_too_large")
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

    def argv(self, schema_path: Path, instructions_path: Path) -> list[str]:
        features = (
            "{" + ",".join(json.dumps(k) + "=" + str(v).lower() for k, v in self.runtime["features"].items()) + "}"
        )
        config = {
            "features": features,
            "model_provider": '"openai"',
            "forced_login_method": '"chatgpt"',
            "approval_policy": '"never"',
            "web_search": '"disabled"',
            "mcp_servers": "{}",
            "project_doc_max_bytes": "0",
            "history.persistence": '"none"',
            "model_reasoning_effort": json.dumps(self.effort),
            "model_instructions_file": json.dumps(str(instructions_path)),
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
        instructions = (
            system + "\nReturn one JSON object with payload_json: a JSON string containing your response "
            "to this canonical contract. Preserve null and absent fields exactly. Contract:\n" + json.dumps(schema)
        )
        data = prompt.encode("utf-8")
        if len(instructions.encode("utf-8")) + len(data) > MAX_REQUEST_BYTES:
            raise TransportError("Codex request exceeds its size limit", reason="request_too_large")
        with tempfile.TemporaryDirectory(prefix="codex-", dir=self.work_root) as work:
            root = Path(work)
            schema_path, instructions_path = root / "schema.json", root / "instructions.txt"
            schema_path.write_text(json.dumps(_WIRE_SCHEMA), encoding="utf-8")
            instructions_path.write_text(instructions, encoding="utf-8")
            schema_path.chmod(0o600)
            instructions_path.chmod(0o600)
            code, out, _ = _run(
                self.argv(schema_path, instructions_path),
                cwd=work,
                env=environment(),
                data=data,
                timeout_s=timeout_s,
                should_stop=should_stop,
            )
        try:
            events = [_json(line) for line in out.splitlines() if line]
            if any(type(event) is not dict for event in events):
                raise ValueError
            failures = [e for e in events if e.get("type") in ("turn.failed", "error")]
            if code or failures:
                # Classify without echoing model text, source excerpts, paths or credentials.
                failure = json.dumps(failures).lower()
                if any(x in failure for x in ("usage_limit", "usage limit", "quota", "rate_limit", "rate limit")):
                    raise TransportError(
                        "ChatGPT usage limit reached; wait for your allowance to reset and resume",
                        reason="quota_exhausted",
                    )
                if any(x in failure for x in ("unauthorized", "authentication", "401", "403")):
                    raise TransportError(
                        "Codex ChatGPT authentication failed; run codex login", reason="authentication_failed"
                    )
                raise TransportError("Codex CLI exchange failed", reason="transport")
            completed = [e for e in events if e.get("type") == "turn.completed"]
            messages = []
            for event in events:
                if event.get("type") not in ("item.started", "item.updated", "item.completed"):
                    continue
                item = event.get("item")
                if type(item) is not dict or item.get("type") not in ("agent_message", "reasoning", "error"):
                    raise ValueError("unexpected tool event")
                if event["type"] == "item.completed" and item["type"] == "agent_message":
                    messages.append(item["text"])
            if len(completed) != 1 or len(messages) != 1:
                raise ValueError
            wire = _json(messages[0])
            if type(wire) is not dict or set(wire) != {"payload_json"} or type(wire["payload_json"]) is not str:
                raise ValueError
            payload = _json(wire["payload_json"])
        except (ValueError, KeyError, TypeError, UnicodeError):
            raise TransportError("Invalid Codex structured response", reason="invalid_response") from None
        return HostReply(payload=payload, usd=None)
