"""Private, bounded diagnostics shared by every full-assessment model host.

Only controller metadata and sanitized rejection reasons enter this log. Prompts,
model answers, source excerpts, provider bodies and stderr are never recorded.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import stat
import sys
import tempfile
import threading
import time
from pathlib import Path

from validators.secret_scan import mask_text

from runtime.analyst_host import HostCancelled, HostTimeout, TransportError

MAX_REASON = 4000
MAX_LOG_BYTES = 8 * 1024 * 1024
FAILURE_CODES = frozenset(
    {
        "transport",
        "connection_timeout",
        "connection_failed",
        "stream_disconnected",
        "tls_error",
        "model_unavailable",
        "timeout",
        "authentication_failed",
        "billing_error",
        "quota_exhausted",
        "rate_limit",
        "server_error",
        "api_error",
        "invalid_request",
        "invalid_response",
        "invalid_response_stream",
        "invalid_response_envelope",
        "invalid_response_payload",
        "unexpected_host_item",
        "incomplete_response",
        "no_result",
        "no_structured_output",
        "response_too_large",
        "request_too_large",
        "output_token_limit",
        "budget_exhausted",
        "host_unavailable",
        "host_arguments",
        "host_configuration",
        "host_exit",
    }
)


class DiagnosticCapture(io.TextIOBase):
    """Drain text output while retaining only a bounded tail for classification."""

    def __init__(self):
        self.text = ""

    def write(self, text):
        self.text = (self.text + text[-16384:])[-16384:]
        return len(text)


class ScannerFailure(ValueError):
    """A fixed scanner identity and classification, without raw scanner output."""

    def __init__(self, scanner: str, reason: str, exit_code: int | None = None, repository_id: str | None = None):
        self.scanner, self.reason, self.exit_code = scanner, reason, exit_code
        self.repository_id = repository_id
        super().__init__(
            (f"{repository_id}: " if repository_id else "")
            + f"{scanner} scanner failed: {reason}"
            + (f" (exit {exit_code})" if exit_code is not None else "")
        )


def safe_reason(reason: str) -> str:
    """Keep structural validation detail, without quoted values or terminal control codes."""
    raw = str(reason)
    if len(raw) > 16384:
        return "Validation detail omitted: diagnostic input limit exceeded [reason truncated]"
    text, _ = mask_text(raw)
    text = re.sub(r"'[^']*'|\"[^\"]*\"|`[^`]*`", "[value]", text)
    text = re.sub(r"https?://\S+|(?<!\w)/(?:[^\s:]+/)+[^\s:]*", "[location]", text)
    text = " ".join("".join(c if c.isprintable() else " " for c in text).split())
    if len(text) > MAX_REASON:
        text = text[: MAX_REASON // 2] + " … [reason truncated] … " + text[-MAX_REASON // 2 :]
    return text


def identifier(value: str) -> str:
    value = str(value)
    if (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,179}", value)
        and "://" not in value
        and mask_text(value)[0] == value
    ):
        return value
    return "id-" + hashlib.sha256(value.encode(errors="backslashreplace")).hexdigest()[:24]


def failure_fields(error: BaseException) -> dict:
    if isinstance(error, ScannerFailure):
        fields = {"scanner": error.scanner, "reason": error.reason, "exit_code": error.exit_code}
        if error.repository_id:
            fields["repository_id"] = identifier(error.repository_id)
        return fields
    if isinstance(error, TransportError):
        result = {"reason": error.reason if error.reason in FAILURE_CODES else "transport"}
        for key in ("exit_code", "http_status"):
            value = getattr(error, key, None)
            if type(value) is int and -255 <= value <= 599:
                result[key] = value
        return result
    if isinstance(error, HostTimeout):
        return {"reason": "timeout"}
    if isinstance(error, (HostCancelled, KeyboardInterrupt)):
        return {"reason": "cancelled"}
    # Review and schema failures are controller-authored; arbitrary exceptions
    # (including provider-library failures) must not bring their text into logs.
    from runtime.assessment_host import MAX_EXCHANGES, ExchangeError, ModelAnswerFailure

    if isinstance(error, ExchangeError):
        fields = {"reason": "validation", "detail": safe_reason(str(error))}
        if isinstance(error, ModelAnswerFailure):
            for field, value in (
                ("exchanges", error.calls_used),
                ("source_read_rounds", error.read_rounds),
                ("rejected_results", error.attempts),
            ):
                if type(value) is int and 0 <= value <= MAX_EXCHANGES:
                    fields[field] = value
        return fields
    result = {"reason": "internal_error"}
    if type(error).__name__ in {
        "OSError",
        "FileNotFoundError",
        "PermissionError",
        "ValueError",
        "TypeError",
        "KeyError",
        "RuntimeError",
        "JSONDecodeError",
    }:
        result["exception"] = type(error).__name__
    if isinstance(error, OSError) and type(error.errno) is int:
        result["errno"] = error.errno
    return result


def transport_summary(error: TransportError) -> str:
    """Operator recovery advice from fixed codes, never from provider prose."""
    reason = failure_fields(error)["reason"]
    if reason == "request_too_large":
        return "request_too_large; the request must be reduced before retrying; --resume alone does not fix it"
    hints = {
        "connection_timeout": "the selected CLI provider timed out; check connectivity and provider availability",
        "connection_failed": "the selected CLI provider could not maintain its connection; check connectivity",
        "stream_disconnected": "the selected CLI provider ended before completion; no answer was accepted",
        "tls_error": "the selected CLI provider could not verify its secure connection; check certificates",
        "model_unavailable": "check that the selected model is supported for this account and host",
        "authentication_failed": "check external credentials or sign in again (Claude, Codex CLI, or Copilot CLI)",
        "billing_error": "the account has no usage left; check provider billing",
        "quota_exhausted": "wait for the subscription allowance to reset",
        "host_arguments": "check that the installed host CLI supports Analyzer's required options",
        "host_configuration": "check the operator-owned host configuration",
        "no_result": "check the host installation and login; no structured result was returned",
        "rate_limit": "wait for provider capacity",
        "invalid_response": "the host returned an invalid structured answer; check the private diagnostic feed",
        "invalid_response_stream": "the selected CLI returned malformed structured output; check its supported version",
        "invalid_response_envelope": "Codex's final message did not match the required JSON envelope",
        "invalid_response_payload": "Codex's final envelope contained an invalid or ambiguous structured payload",
        "unexpected_host_item": "Codex emitted a tool or unsupported item; check CLI isolation before retrying",
        "incomplete_response": "Codex did not return one completed turn with a final answer",
    }
    return (
        reason + "; " + hints.get(reason, "check the selected host") + "; then continue compatible work with --resume"
    )


class DiagnosticLog:
    def __init__(self, directory: Path, run_id: str):
        directory.mkdir(mode=0o700, exist_ok=True)
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o077:
            raise OSError("diagnostic directory must be private and owned")
        self.directory = Path(tempfile.mkdtemp(prefix="attempt-", dir=directory))
        self.path = self.directory / "events.jsonl"
        fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.run_id = identifier(run_id)
        self.lock = threading.RLock()
        self.calls = 0
        self.disabled = False
        self.emit("attempt_start")

    def emit(self, event: str, **fields) -> None:
        with self.lock:
            if self.disabled:
                return
            row = {
                "event": event,
                "run_id": self.run_id,
                "attempt_id": self.directory.name,
                "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                **fields,
            }
            data = (json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n").encode()
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "ab") as stream:
                    info = os.fstat(stream.fileno())
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_nlink != 1
                        or info.st_uid != os.getuid()
                        or info.st_mode & 0o077
                        or info.st_size + len(data) > MAX_LOG_BYTES
                    ):
                        raise OSError("diagnostic file unavailable or full")
                    stream.write(data)
            except OSError:
                self.disabled = True
                print(
                    "⚠ assessment diagnostics disabled: private log unavailable or size limit reached", file=sys.stderr
                )

    def job(self, role: str, selector: str):
        return JobTrace(self, role, selector)


class JobTrace:
    def __init__(self, log: DiagnosticLog, role: str, selector: str):
        self.log = log
        from runtime.assessment_jobs import digest

        self.fields = {
            "role": identifier(role),
            "selector": identifier(selector),
            "job_id": "job-" + digest({"role": role, "selector": selector})[:24],
        }

    def emit(self, event: str, **fields):
        self.log.emit(event, **self.fields, **fields)

    def wrap(self, transport):
        with self.log.lock:
            self.log.calls += 1
            call_id = f"call-{self.log.calls:06d}"
        return RecordedTransport(transport, self, call_id)


class RecordedTransport:
    def __init__(self, inner, trace: JobTrace, call_id: str):
        self.inner, self.trace, self.call_id = inner, trace, call_id
        host = getattr(inner, "inner", inner)
        self.host_fields = {"host": identifier(type(host).__name__)}
        model = getattr(host, "model", None) or getattr(getattr(host, "profile", None), "model", None)
        if isinstance(model, str):
            self.host_fields["model"] = identifier(model)
        events_path = getattr(host, "events_path", None)
        if isinstance(events_path, Path):
            self.host_fields["host_event_attempt"] = identifier(events_path.parent.name)
            self.host_fields["host_event_file"] = identifier(events_path.name)
        bind = getattr(inner, "bind_diagnostic", None)
        if callable(bind):
            bind(f"{trace.fields['job_id']} {trace.fields['selector']} {call_id}")

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        self.trace.emit("call_start", call_id=self.call_id, **self.host_fields)
        started = time.monotonic()
        try:
            reply = self.inner.invoke(system, prompt, schema, timeout_s, should_stop)
        except BaseException as error:
            self.trace.emit(
                "call_failed",
                call_id=self.call_id,
                seconds=round(time.monotonic() - started, 3),
                **failure_fields(error),
            )
            raise
        self.trace.emit("call_returned", call_id=self.call_id, seconds=round(time.monotonic() - started, 3))
        return reply

    def on_correction(self, reason: str):
        self.trace.emit("answer_rejected", call_id=self.call_id, detail=safe_reason(reason))
        notice = getattr(self.inner, "on_correction", None)
        if callable(notice):
            notice(reason)
