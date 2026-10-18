"""Scanner execution and validation; callers own selection and failure policy."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from jsonschema import Draft202012Validator


def run_python(
    arguments: list[str], *, timeout_s: float, cwd: Path | None = None, capture: bool = True
) -> subprocess.CompletedProcess:
    """Run a bundled Python scanner without a shell and with a finite deadline."""
    return subprocess.run(
        [sys.executable, *arguments],
        stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
        stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
        check=False,
    )


def validate_output(document: dict, schema: dict) -> None:
    """Reject malformed output and producer error stubs, even on exit zero."""
    Draft202012Validator(schema).validate(document)
    if "parse_error" in document:
        raise ValueError("scanner reported a parse error")


def call_in_process(name, call):
    """Capture scanner diagnostics while preserving assessment failure categories."""
    import contextlib

    from runtime.assessment_diagnostics import DiagnosticCapture, ScannerFailure

    captured = DiagnosticCapture()
    try:
        with contextlib.redirect_stderr(captured), contextlib.redirect_stdout(captured):
            code = call()
    except (OSError, ValueError, KeyError, UnicodeError) as error:
        reason = "filesystem_error" if isinstance(error, OSError) else "invalid_input"
        raise ScannerFailure(name, reason) from None
    if code:
        text = captured.text.lower()
        reason = "execution_error"
        if "failed to load checks" in text or "checks file" in text or "plugin root" in text:
            reason = "scanner_configuration"
        elif any(word in text for word in ("parse", "syntax", "invalid json", "invalid yaml")):
            reason = "input_parse_error"
        raise ScannerFailure(name, reason, code if type(code) is int else None)
