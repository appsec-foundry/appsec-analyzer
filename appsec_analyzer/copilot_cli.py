"""Bounded, tool-less GitHub Copilot CLI exchanges for full assessments."""

from __future__ import annotations

import json
import math
import os
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError, ValidationError

from appsec_analyzer import resource_root

_scripts = str(resource_root() / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from runtime.analyst_host import HostCancelled, HostReply, HostTimeout, TransportError

SUPPORTED_VERSION = "1.0.101"
MAX_BYTES = 1_048_576
MAX_REQUEST_BYTES = 320_000
MAX_AI_CREDITS = 30


def prompt_capacity(system, schema):
    suffix = "\nReturn exactly one JSON value matching this JSON Schema. Do not use Markdown fences or add prose.\n"
    fixed = (system + suffix + json.dumps(schema, ensure_ascii=False, separators=(",", ":"), allow_nan=False)).encode(
        "utf-8"
    )
    return max(0, MAX_REQUEST_BYTES - len(fixed) - 2)


def _json(data: str):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("ambiguous JSON")
            result[key] = value
        return result

    def invalid_constant(_value):
        raise ValueError("non-finite JSON")

    def finite(value):
        number = float(value)
        if not math.isfinite(number):
            raise ValueError("non-finite JSON")
        return number

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant, parse_float=finite)


def environment() -> dict[str, str]:
    allowed = (
        "PATH",
        "HOME",
        "COPILOT_HOME",
        "XDG_CONFIG_HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "SYSTEMROOT",
        "LANG",
    )
    return {key: os.environ[key] for key in allowed if key in os.environ}


def _stop(proc):
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(proc.pid, sig)
        except ProcessLookupError:
            break
        if sig == signal.SIGTERM:
            time.sleep(0.1)
    proc.wait(timeout=5)


def _feed(pipe, data):
    try:
        pipe.write(data)
        pipe.flush()
    except BrokenPipeError:
        pass
    finally:
        pipe.close()


def _run(argv, *, cwd, env, data=b"", timeout_s=10, should_stop=lambda: False):
    if should_stop():
        raise HostCancelled("Copilot CLI call cancelled before transmission")
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
        raise TransportError("Copilot CLI could not be started", reason="host_unavailable") from None
    import threading

    threading.Thread(target=_feed, args=(proc.stdin, data), daemon=True).start()
    streams = {proc.stdout: bytearray(), proc.stderr: bytearray()}
    deadline = time.monotonic() + timeout_s
    try:
        with selectors.DefaultSelector() as selected:
            for pipe in streams:
                selected.register(pipe, selectors.EVENT_READ)
            while selected.get_map():
                if should_stop():
                    raise HostCancelled("Copilot CLI call cancelled")
                if time.monotonic() >= deadline:
                    raise HostTimeout("Copilot CLI call exceeded its time limit")
                for key, _ in selected.select(timeout=0.1):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selected.unregister(key.fileobj)
                        continue
                    streams[key.fileobj].extend(chunk)
                    if sum(map(len, streams.values())) > MAX_BYTES:
                        raise TransportError("Copilot CLI output exceeds its size limit", reason="response_too_large")
            while proc.poll() is None:
                if should_stop():
                    raise HostCancelled("Copilot CLI call cancelled")
                if time.monotonic() >= deadline:
                    raise HostTimeout("Copilot CLI call exceeded its time limit")
                time.sleep(0.05)
        return proc.returncode, bytes(streams[proc.stdout]), bytes(streams[proc.stderr])
    finally:
        _stop(proc)
        for pipe in (proc.stdout, proc.stderr):
            pipe.close()


def _failure(stdout: bytes, stderr: bytes, code: int) -> TransportError:
    text = (stdout[-16_384:] + b" " + stderr[-16_384:]).decode("utf-8", errors="replace").lower()
    rules = (
        ("quota_exhausted", ("usage limit", "quota", "ai credits", "credit limit")),
        ("rate_limit", ("rate limit", "429")),
        ("authentication_failed", ("unauthorized", "authentication", "401", "403", "not logged in")),
        ("model_unavailable", ("model not found", "model is not available", "unsupported model")),
        ("connection_timeout", ("timed out", "timeout")),
        ("connection_failed", ("failed to connect", "connection reset", "network error")),
    )
    reason = next((name for name, markers in rules if any(marker in text for marker in markers)), "host_failure")
    return TransportError("Copilot CLI exchange failed", reason=reason, exit_code=code)


def preflight(*, repositories=()) -> dict:
    executable = shutil.which("copilot")
    if executable is None or os.name != "posix":
        raise ValueError("copilot-cli requires GitHub Copilot CLI 1.0.101 on Linux or macOS")
    executable = str(Path(executable).resolve())
    from appsec_analyzer.profiles import ProfileError, reject_source_paths

    try:
        reject_source_paths([executable], repositories)
    except ProfileError:
        raise ValueError("Copilot CLI executable must be outside the analyzed repositories") from None
    with tempfile.TemporaryDirectory(prefix="appsec-copilot-check-") as work:
        code, out, _ = _run([executable, "--version"], cwd=work, env=environment())
    if code or out.strip() != f"GitHub Copilot CLI {SUPPORTED_VERSION}".encode():
        raise ValueError(f"copilot-cli requires reviewed GitHub Copilot CLI version {SUPPORTED_VERSION}")
    return {"executable": executable, "version": SUPPORTED_VERSION}


class CopilotCliTransport:
    def __init__(self, work_root: Path, model: str, effort: str, runtime: dict):
        if not isinstance(model, str) or not model or model.lower() == "auto":
            raise ValueError("Copilot CLI requires an explicit model")
        if effort not in ("none", "minimal", "low", "medium", "high", "xhigh", "max"):
            raise ValueError("invalid Copilot reasoning effort")
        self.work_root, self.model, self.effort, self.runtime = work_root, model, effort, runtime

    def argv(self, cwd: Path) -> list[str]:
        return [
            self.runtime["executable"],
            "--no-auto-update",
            "--no-color",
            "--no-bash-env",
            "--no-custom-instructions",
            "--no-ask-user",
            "--no-remote",
            "--no-remote-export",
            "--disable-builtin-mcps",
            "--available-tools",
            "--secret-env-vars",
            "COPILOT_GITHUB_TOKEN,GH_TOKEN,GITHUB_TOKEN",
            "--model",
            self.model,
            "--reasoning-effort",
            self.effort,
            "--max-ai-credits",
            str(MAX_AI_CREDITS),
            "--log-level",
            "none",
            "--log-dir",
            str(cwd / "logs"),
            "--silent",
            "--output-format",
            "text",
            "-C",
            str(cwd),
        ]

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        if type(system) is not str or type(prompt) is not str or type(schema) is not dict:
            raise TransportError("Invalid Copilot request", reason="invalid_request")
        if type(timeout_s) is not int or not 1 <= timeout_s <= 3600:
            raise TransportError("Invalid Copilot timeout", reason="invalid_request")
        try:
            if any(
                isinstance(value, str) and not value.startswith("#")
                for key, value in _schema_refs(schema)
                if key in ("$ref", "$dynamicRef", "$recursiveRef")
            ):
                raise ValueError("external schema references are unavailable")
            validator = Draft202012Validator(schema)
            Draft202012Validator.check_schema(schema)
        except (SchemaError, TypeError, ValueError, RecursionError):
            raise TransportError("Unsupported Copilot output contract", reason="invalid_request") from None
        instructions = (
            system
            + "\nReturn exactly one JSON value matching this JSON Schema. Do not use Markdown fences or add prose.\n"
            + json.dumps(schema, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
        )
        data = (instructions + "\n\n" + prompt).encode("utf-8")
        if len(data) > MAX_REQUEST_BYTES:
            raise TransportError("Copilot request exceeds its size limit", reason="request_too_large")
        with tempfile.TemporaryDirectory(prefix="copilot-", dir=self.work_root) as work:
            cwd = Path(work)
            code, out, err = _run(
                self.argv(cwd),
                cwd=cwd,
                env=environment(),
                data=data,
                timeout_s=timeout_s,
                should_stop=should_stop,
            )
        if code:
            raise _failure(out, err, code)
        try:
            answer = _json(out.decode("utf-8", errors="strict").strip())
            if not isinstance(answer, (dict, list)) or not validator.is_valid(answer):
                raise ValueError("response does not match the schema")
        except (ValueError, UnicodeError, ValidationError, RecursionError):
            raise TransportError(
                "Invalid Copilot structured response", reason="invalid_response", exit_code=code
            ) from None
        return HostReply(payload=answer, usd=None)


def _schema_refs(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield key, item
            yield from _schema_refs(item)
    elif isinstance(value, list):
        for item in value:
            yield from _schema_refs(item)
