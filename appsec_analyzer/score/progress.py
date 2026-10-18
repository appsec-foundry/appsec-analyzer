"""Persistent score steps on stderr, with a live current step on terminals."""

from __future__ import annotations

import os
import re
import sys
import threading
import time
import unicodedata
from collections.abc import Callable
from typing import TextIO
from urllib.parse import urlsplit, urlunsplit

from appsec_analyzer.score.events import ScoreEvent

_PHASES = {1: "Repository", 2: "Security checks", 3: "Result"}
_STEPS = {
    "Cloning Git repository...": (1, "Cloning Git repository"),
    "Reading repository sources...": (1, "Reading repository sources"),
    "Preparing source scan...": (1, "Preparing source scan"),
    "Discovering application routes...": (2, "Discovering application routes"),
    "Checking architecture coverage...": (2, "Checking architecture coverage"),
    "Scanning configuration and infrastructure...": (2, "Scanning configuration and infrastructure"),
    "Scanning source code...": (2, "Scanning source code"),
    "Calculating security score...": (3, "Calculating security score"),
    "Checking source consistency...": (3, "Checking source consistency"),
}
_SCANNER_STEPS = {
    "route-inventory": "Discovering application routes",
    "architecture-coverage": "Checking architecture coverage",
    "config-iac": "Scanning configuration and infrastructure",
    "source-auth": "Scanning source code",
}
_SCANNER_RESULTS = {
    f"Scanner result: {scanner}: {status}": (detail, "done" if status == "complete" else status)
    for scanner, detail in _SCANNER_STEPS.items()
    for status in ("complete", "failed", "missing", "invalid")
}


def _repository_label(selection: str) -> str:
    """Identify the operator's selection without URL credentials or terminal controls."""
    if (
        not isinstance(selection, str)
        or not selection.strip()
        or len(selection) > 4096
        or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in selection)
    ):
        return "selected repository"
    try:
        if "://" in selection:
            parsed = urlsplit(selection)
            if parsed.scheme not in {"https", "ssh"} or not parsed.hostname:
                return "selected repository"
            host = parsed.hostname
            authority = f"[{host}]" if ":" in host else host
            if parsed.port is not None:
                authority += f":{parsed.port}"
            label = urlunsplit((parsed.scheme, authority, parsed.path, "", ""))
        elif ":" in selection and not selection.startswith(("/", "./", "../", "~")):
            match = re.fullmatch(r"(?:[\w.-]+@)?([A-Za-z0-9.-]+):([A-Za-z0-9._~/-]+)", selection)
            if match is None:
                return "selected repository"
            label = f"{match[1]}:{match[2]}"
        else:
            label = os.path.abspath(os.path.expanduser(selection))
    except (OSError, ValueError):
        return "selected repository"
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"} for char in label):
        return "selected repository"
    return label if len(label) <= 240 else "..." + label[-237:]


def _styled_repository_label(selection: str, style: Callable[..., str]) -> str:
    """Emphasize the project within the safe label without changing its text."""
    label = _repository_label(selection)
    end = len(label.rstrip("/"))
    if not end or label == "selected repository":
        return style(label, "accent", "bold")
    start = label.rfind("/", 0, end) + 1
    if not start and not label.startswith(("/", "...")) and ":" in label:
        start = label.rfind(":", 0, end) + 1
    return style(label[:start], "muted") + style(label[start:end], "accent", "bold") + style(label[end:], "muted")


def _terminal_style(stream: TextIO) -> Callable[..., str]:
    """Load the lightweight shared theme before the analysis runtime imports."""
    from appsec_analyzer.engine import initialize

    initialize()
    from renderers.term_style import Style

    return Style.for_stream(stream)


class ScoreProgress:
    """Render trusted phases and a safe operator-selected repository label."""

    def __init__(
        self, stream: TextIO | None = None, *, repository: str | None = None, style: Callable[..., str] | None = None
    ):
        self.stream = stream if stream is not None else sys.stderr
        self._style = style if style is not None else _terminal_style(self.stream)
        self._title = "Calculating security score"
        self._repository = repository
        self.terminal = self.stream.isatty() and os.environ.get("TERM") != "dumb"
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._finished = False
        self._frame = 0
        self._phase = 1
        self._detail = "Loading analysis runtime"
        self._step_finished = False

    def __enter__(self):
        self._started = self._step_started = time.monotonic()
        title = self._title
        if self._repository is not None:
            title += " for " + _styled_repository_label(self._repository, self._style)
        self._write(title + "\n")
        self._heading()
        self._active()
        if self.terminal:
            self._thread = threading.Thread(target=self._animate, daemon=True, name="score-progress")
            self._thread.start()
        return self

    def _write(self, text: str) -> None:
        self.stream.write(text)
        self.stream.flush()

    def _heading(self) -> None:
        self._write(f"\n  [{self._phase}/3] {_PHASES[self._phase]}\n")

    def _row(self, status: str) -> str:
        elapsed = time.monotonic() - self._step_started
        role = {
            "running": "accent",
            "done": "ok",
            "failed": "critical",
            "invalid": "critical",
            "missing": "warn",
            "cancelled": "warn",
        }[status]
        label = self._style(f"{f'[{status}]':<11}", role)
        return f"    {label} {self._detail:<43} {elapsed:>6.1f}s"

    def _active(self) -> None:
        if self.terminal:
            spinner = "|/-\\"[self._frame % 4]
            self._frame += 1
            self._write(f"\r\x1b[2K{self._row('running')}  {spinner}")
        else:
            self._write(self._row("running") + "\n")

    def _complete_step(self, status: str = "done") -> None:
        prefix = "\r\x1b[2K" if self.terminal else ""
        self._write(prefix + self._row(status) + "\n")
        self._step_finished = True

    def _animate(self) -> None:
        while not self._stop.wait(0.1):
            with self._lock:
                if not self._finished and not self._step_finished:
                    self._active()

    def __call__(self, message: ScoreEvent | str) -> None:
        # Strings are accepted only for retained callers of the old renderer.
        if isinstance(message, ScoreEvent):
            detail = _SCANNER_STEPS.get(message.scanner)
            outcome = (
                (detail, "done" if message.status == "complete" else message.status)
                if detail and message.status
                else None
            )
            step = (
                (2, detail)
                if detail
                else {
                    "clone": (1, "Cloning Git repository"),
                    "read_sources": (1, "Reading repository sources"),
                    "snapshot": (1, "Preparing source scan"),
                    "calculate": (3, "Calculating security score"),
                    "verify_sources": (3, "Checking source consistency"),
                }.get(message.step)
            )
        else:
            outcome = _SCANNER_RESULTS.get(message)
            step = _STEPS.get(message)
        if outcome is not None:
            with self._lock:
                detail, status = outcome
                if not self._finished and not self._step_finished and detail == self._detail:
                    self._complete_step(status)
            return
        if step is None:
            return
        with self._lock:
            if self._finished:
                return
            phase, detail = step
            if (phase, detail) == (self._phase, self._detail):
                return
            if not self._step_finished:
                self._complete_step()
            if phase != self._phase:
                self._phase = phase
                self._heading()
            self._detail = detail
            self._step_started = time.monotonic()
            self._step_finished = False
            self._active()

    def finish(self, verdict: str) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        with self._lock:
            if self._finished:
                return
            self._finished = True
            if not self._step_finished:
                self._complete_step({"cancelled": "cancelled", "failed": "failed"}.get(verdict, "done"))
            status = {
                "scored": "Completed in",
                "undetermined": "Completed in",
                "incomplete": "Incomplete scan after",
                "failed": "Stopped after",
                "cancelled": "Cancelled by user after",
            }[verdict]
            role = {"incomplete": "warn", "failed": "critical", "cancelled": "warn"}.get(verdict, "ok")
            self._write("\n" + self._style(f"  {status} {time.monotonic() - self._started:.1f}s", role) + "\n\n")

    def __exit__(self, exc_type, exc_value, traceback):
        if not self._finished:
            self.finish("cancelled" if exc_type is KeyboardInterrupt else "failed")
