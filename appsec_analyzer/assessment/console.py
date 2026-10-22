"""Assessment progress feed and terminal presentation."""

from __future__ import annotations

import json
import re
import shutil
import sys
import textwrap
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

from appsec_analyzer.engine import initialize

initialize()
from renderers.term_style import ANSI_RE, SPINNER, Style, logo, plugin_version

ASSESS_PAUSED_EXIT = 3


def _duration(seconds: float) -> str:
    minutes, rest = divmod(round(seconds), 60)
    return f"{minutes}m{rest:02d}s" if minutes else f"{rest}s"


def _minutes(seconds: float) -> str:
    return "<1m" if seconds < 60 else f"{int(seconds // 60)}m"


def _elapsed(seconds: float) -> str:
    """Minutes below an hour, then hours and minutes: ``13m``, ``1h05m``."""
    hours, minutes = divmod(int(seconds // 60), 60)
    return _minutes(seconds) if not hours else f"{hours}h" + (f"{minutes:02d}m" if minutes else "")


def _count_noun(count: int, noun: str) -> str:
    """``count`` with ``noun`` in singular or plural, for console result lines."""
    if count != 1:
        noun = noun[:-1] + "ies" if noun.endswith("y") and noun[-2:-1] not in "aeiou" else noun + "s"
    return f"{count} {noun}"


def model_failure_lines(error) -> list[str]:
    """Present a rejected analysis using job context, keeping technical IDs in diagnostics."""
    from runtime.assessment_diagnostics import safe_reason
    from runtime.assessment_host import ModelAnswerFailure

    if not isinstance(error, ModelAnswerFailure):
        return []
    job = getattr(error, "assessment_job", {})
    role = job.get("role")
    phase = {"stride_analyzer": "Threat analysis", "architecture_analyst": "Architecture"}.get(
        role, _AssessmentConsole.ROLE_LABELS.get(role, "Analysis")
    )
    lines = [f"✗ assessment stopped: {phase} could not produce a valid result"]
    label = safe_reason(job.get("label", ""))
    batch = re.search(r":(\d+)/(\d+)$", job.get("selector", ""))
    if label:
        lines.append(
            f"  {job.get('subject', 'Component')}: {label}" + (f" · batch {batch[1]} of {batch[2]}" if batch else "")
        )
    if error.attempts:
        lines.append(f"  The model's answer failed validation after {_count_noun(error.attempts, 'attempt')}.")
    if error.calls_used is not None:
        lines.append(f"  Job exchanges used: {error.calls_used}; source-read rounds: {error.read_rounds or 0}.")
    issues = getattr(error.rejection, "surface_issues", ())
    if issues:
        for issue in issues[:3]:
            location = safe_reason(f"{issue['file']}:{issue['line']}")
            reason = (
                "the required source line was not read"
                if issue["reason"] == "unread"
                else "the source was read, but the model's decision cites a different source"
            )
            lines.append(f"  {location}: {reason}.")
    elif error.rejection:
        lines.append("  Reason: " + safe_reason(str(error.rejection)))
    else:
        lines.append("  Reason: " + safe_reason(job.get("reason", str(error))))
    lines += [
        "  Accepted steps are kept. With unchanged source and settings and time remaining, retry the same command",
        "  with --resume instead of --rebuild. If the rejection repeats, investigate it before retrying again.",
    ]
    diagnostics = getattr(error, "diagnostic_path", None)
    if diagnostics:
        lines.append(f"  Diagnostics: {diagnostics}")
    return lines


class _AssessmentProgress:
    """The run's progress as JSON lines (``--progress-file``), for a follower such as a skill's monitor.

    The console grid is for people: padded columns and wrapped details. A
    follower reads named fields instead, one record per append, so it never
    parses columns or joins continuation lines. ``end`` is the last record of
    every run that opened the file, whatever ended it.
    """

    path: Path | None = None
    last_retry: tuple[str, float] | None = None
    # Exit code -> the end record's status; any other code failed.
    STATUS = {0: "complete", 20: "complete", ASSESS_PAUSED_EXIT: "paused", 130: "interrupted"}

    @classmethod
    def open(cls, path: str | None) -> None:
        cls.path = Path(path) if path else None
        cls.last_retry = None
        if cls.path:
            # Replaced, so a follower never reads an earlier run's events as this run's.
            cls._append("", mode="w")

    @classmethod
    def emit(cls, event: str, **fields) -> None:
        if cls.path:
            fields.setdefault("time", time.strftime("%H:%M:%S"))
            cls._append(json.dumps({"event": event, **fields}, ensure_ascii=False) + "\n")

    @classmethod
    def end(cls, code: int) -> None:
        resumable = code in (ASSESS_PAUSED_EXIT, 130)
        cls.emit("end", status=cls.STATUS.get(code, "failed"), exit_code=code, resumable=resumable)
        cls.path = None

    @classmethod
    def note_retry(cls, message: str) -> None:
        match = re.search(r"model call failed \(([a-z_]+)\)", message)
        if match:
            cls.last_retry = (match.group(1), time.monotonic())

    @classmethod
    def recent_rate_limit(cls) -> bool:
        return bool(cls.last_retry and cls.last_retry[0] == "rate_limit" and time.monotonic() - cls.last_retry[1] < 300)

    @classmethod
    def _append(cls, text: str, mode: str = "a") -> None:
        try:
            with cls.path.open(mode, encoding="utf-8") as stream:
                stream.write(text)
        except OSError as exc:
            # A follower losing its feed must not end the assessment; the console still reports.
            cls.path = None
            print(f"⚠ progress file disabled: {exc.strerror or exc}", file=sys.stderr, flush=True)


class _AssessmentConsole:
    """The run's console view: every line in one fixed column grid.

    Each line reads ``TIME  PHASE  EVENT  PROGRESS  ELAPSED  LEFT  DETAIL``.
    PHASE is numbered within this run, so a skipped phase (abuse cases)
    shortens N. EVENT is ``start`` and ``done`` for a phase's bounds, ``✓``
    for a finished component, ``·`` for progress, and ``⚠`` (stalled or
    stopped model call, plugin change) or
    ``↻`` (rejected answer) for lines that need attention. PROGRESS, ELAPSED
    and LEFT always describe the whole run. DETAIL describes the phase and
    comes last, so its length never shifts a column; a ``done`` line's
    detail starts with the phase's duration.

    PROGRESS counts finished work. Once the component count is known
    (``plan_components``), Controls and STRIDE weigh per component. LEFT
    extrapolates the speed this run measured once a component has finished;
    before that it scales a nominal run time to the planned phases and
    components, so it changes as the run learns its size. Before the component
    count is known PROGRESS says ``planning``. Time stamps and durations read
    one clock.

    Off a terminal (CI, logs) a progress line follows a change after
    ``PROGRESS_SECONDS`` and comes at the latest after ``HEARTBEAT_SECONDS``;
    a terminal gets one progress line rewritten in place instead, redrawn
    every ``TICK_SECONDS`` with a spinner, a progress bar, each running model
    call's age and activity, or the running controller step's age. On a
    terminal the columns carry colour (``renderers/term_style``); an injected
    writer is a log and stays plain. Each STRIDE component and each
    verified abuse case gets its own line in both. ``--verbose`` adds every
    step and model call as progress lines and keeps the terminal's status
    line; ``--quiet`` prints nothing. Cost is never shown mid-run.
    """

    # Off a terminal: a changed subject or share is shown after this quiet
    # interval, an unchanged one after the heartbeat interval.
    PROGRESS_SECONDS = 120
    HEARTBEAT_SECONDS = 300
    # On a terminal: how often the status line is redrawn (fast enough to turn
    # the spinner), and how many running calls it names before "+N more".
    TICK_SECONDS = 0.2
    TICK_CALLS = 2
    # Width of the status line's progress bar.
    BAR_WIDTH = 12
    # Colour of a row's phase and event columns, by event.
    EVENT_ROLES = {"start": "accent", "done": "ok", "✓": "ok", "⚠": "warn", "↻": "warn"}
    # Reader-facing names of the model roles in liveness and completion lines.
    ROLE_LABELS = {
        "recon_scanner": "discovery",
        "architecture_analyst": "architecture",
        "trust_boundary_analyst": "trust boundaries",
        "control_analyst": "controls",
        "stride_analyzer": "STRIDE",
        "evidence_verifier": "evidence review",
        "threat_merger": "merge review",
        "actor_discoverer": "actor discovery",
        "architect_reviewer": "architect review",
        "post_stride_synthesizer": "root-cause synthesis",
        "abuse_case_deriver": "abuse-case derivation",
        "abuse_case_verifier": "abuse-case verification",
        "ms_renderer": "management summary",
        "secarch_renderer": "security architecture",
    }

    # Step prefixes mapped onto the console phases, in run order.
    PHASES = (
        ("Collecting the deterministic route", "Reconnaissance"),
        ("Discovering every selected repository", "Reconnaissance"),
        ("Discovering repository", "Reconnaissance"),
        ("Reviewing evidenced cross-repository", "Architecture"),
        ("Analyzing local architecture", "Architecture"),
        ("Measuring the boundary source context", "Trust boundaries"),
        ("Reviewing trust crossing batch", "Trust boundaries"),
        ("Reviewing trust crossing", "Trust boundaries"),
        ("Assessing controls", "Controls"),
        ("Running deterministic source scanners", "Threat analysis"),
        ("Analyzing all STRIDE categories", "Threat analysis"),
        ("Finished STRIDE job", "Threat analysis"),
        ("Independently verifying evidence", "Threat analysis"),
        ("Analyzed component", "Threat analysis"),
        ("Reviewing merge candidates", "Consolidation"),
        ("Building the deterministic route inventory", "Consolidation"),
        ("Evaluating posture producers", "Consolidation"),
        ("Reviewing findings as architect", "Consolidation"),
        ("Resolving actors", "Consolidation"),
        ("Ranking findings", "Consolidation"),
        # The model is built before abuse verification, which binds its steps
        # to the ranked findings.
        ("Building the assessment model", "Consolidation"),
        ("Matching abuse cases", "Abuse cases"),
        ("Deriving application-specific business abuse cases", "Abuse cases"),
        ("Verifying abuse case", "Abuse cases"),
        ("Reviewing promoted findings as architect", "Abuse cases"),
        # Root causes cover the findings abuse verification adds.
        ("Synthesizing cross-finding", "Finalization"),
        ("Updating the assessment model", "Finalization"),
        ("Rendering the report", "Finalization"),
        ("Stage 2:", "Finalization"),
        ("Running the quality gates", "Finalization"),
        ("Publishing", "Finalization"),
    )
    # Steps whose subject (component, section, abuse case) is worth a
    # progress line; model reads and per-call results stay behind --verbose.
    SUBJECTS = (
        "Discovering repository",
        "Analyzing local architecture",
        "Reviewing trust crossing batch",
        "Reviewing trust crossing",
        "Assessing controls",
        "Analyzing all STRIDE categories",
        "Reviewing findings as architect",
        "Reviewing promoted findings as architect",
        "Verifying abuse case",
        "Stage 2:",
    )
    # Subjects that also get a permanent line each, so the run's console
    # names every discovered repository, analyzed component and verified abuse case.
    LISTED = ("Discovering repository", "Analyzing all STRIDE categories", "Verifying abuse case")
    # Listed names come from repository files and model output.
    _NAME_MAX = 100
    # What a phase's subjects are, for progress lines and the done line's count.
    NOUNS = {
        "Discovering repository": "repository",
        "Analyzing local architecture": "repository",
        "Reviewing trust crossing batch": "batch",
        "Reviewing trust crossing": "crossing",
        "Assessing controls": "component",
        "Analyzing all STRIDE categories": "component",
        "Reviewing findings as architect": "architect review",
        "Reviewing promoted findings as architect": "architect review",
        "Verifying abuse case": "abuse case",
        "Stage 2:": "report section",
    }
    # Prefix of a phase's result step: "<RESULT><phase>: <what it produced>".
    RESULT = "Phase result: "
    _POSITION = re.compile(r"\s*\((\d+)/(\d+)\)$")
    # Expected share of a run's wall clock per phase, in points. Measured as
    # the mean phase durations of two single-repository standard runs of nine
    # components (Juice Shop, 2026-10-16); threat analysis includes the
    # source scanners and evidence reviews. Controls and threat analysis scale
    # with the component count, the other phases stay fixed. A display
    # estimate only: the remaining time follows the speed the run measures.
    WEIGHTS = {
        "Reconnaissance": 3,
        "Architecture": 4,
        "Trust boundaries": 12,
        "Controls": 6,
        "Threat analysis": 50,
        "Consolidation": 6,
        "Abuse cases": 7,
        "Finalization": 12,
    }
    PER_COMPONENT = {"Controls": 6 / 9, "Threat analysis": 50 / 9}
    # Wall clock of the nine-component, all-phases run those weights describe
    # (Juice Shop, 33m), for the remaining time before this run has a speed of
    # its own. It is a prior: the measured speed replaces it.
    NOMINAL_SECONDS = 33 * 60
    NOMINAL_WEIGHT = sum(WEIGHTS.values())
    _NAME_WIDTH = max(len(name) for name in WEIGHTS)
    # "n/N " before the phase name, then the event column.
    _PHASE_WIDTH = _NAME_WIDTH + 4
    _EVENT_WIDTH = 5

    def __init__(self, verbose: bool, write=None, live: bool | None = None, clock=time.time):
        self.verbose = verbose
        self._out = write or self._line
        # The in-place status line needs a terminal; an injected writer is a log.
        self.live = (write is None and sys.stderr.isatty()) if live is None else live
        self.st = Style.for_stream(sys.stderr) if write is None else Style(False)
        self.frame = 0
        # One clock for time stamps and durations, so each line's figures agree.
        self.clock = clock
        self.plan = list(self.WEIGHTS)
        self.phase, self.started, self.finished_jobs = None, 0.0, 0
        # Finished share of the current phase and of the run, both 0..1 and never falling.
        self.fraction, self.done = 0.0, 0.0
        self.components = None
        # The current subject, the phase's largest numbered subject set, and
        # whether the phase reports positions at all.
        self.current, self.count, self.positioned = "", None, False
        self.parts: dict = {}
        # Roles whose last answer was rejected: their next answer is the correction.
        self.correcting: set = set()
        # Components in analysis, in start order: name -> finished and planned
        # STRIDE jobs and the current stage; and the components finished.
        self.units: dict[str, dict] = {}
        self.units_done = 0
        # Corrected answers per role in the current phase (MR-17).
        self.corrections: Counter = Counter()
        self.results: dict[str, str] = {}
        self.review_coverage: dict[str, dict[str, str]] = {}
        self.headed, self.shown = False, None
        # Called once a phase has started, e.g. to report a plugin change at once.
        self.on_phase = None
        self.run_started = self.last = self.clock()
        # Model calls in flight (_ReportedTransport registers itself) and the
        # last controller step with its start, for the terminal's status line.
        self.running: dict[int, Any] = {}
        self._call_notices: set[tuple[str, str]] = set()
        self.prompting = False
        self.activity, self.activity_started = "", time.monotonic()

    def start_ticker(self) -> None:
        """On a terminal, redraw the status line every ``TICK_SECONDS`` until the run stops."""
        if not self.live:
            return
        _AssessmentConsole._stopped.clear()

        def tick():
            while not _AssessmentConsole._stopped.wait(self.TICK_SECONDS):
                try:
                    self.tick()
                except Exception:  # noqa: BLE001 - a status redraw must never print a traceback or end the run
                    pass

        threading.Thread(target=tick, daemon=True).start()

    @staticmethod
    def stop() -> None:
        """End the ticker and remove the status line, so no redraw follows the run's last message."""
        with _AssessmentConsole._lock:
            _AssessmentConsole._stopped.set()
            _AssessmentConsole.clear_status()

    def tick(self) -> None:
        """Redraw the status line: what runs right now and for how long."""
        if not self.phase or self.prompting:
            return
        now = time.monotonic()
        # Copied first: calls register and leave from their own threads.
        calls = sorted(list(self.running.values()), key=lambda call: call.started)
        if calls:
            shown = []
            for call in calls:
                name = call.name or "model call"
                if not self.verbose:
                    name = name.partition(" [job-")[0]
                shown.append(f"{name} {_duration(now - call.started)} {call.state()}")
            more = len(shown) - self.TICK_CALLS
            working = " · ".join(shown[: self.TICK_CALLS]) + (f" · +{more} more" if more > 0 else "")
        elif self.activity:
            working = f"{self.activity} · {_duration(now - self.activity_started)}"
        else:
            working = ""
        self.frame += 1
        self._status(self._row("·", " · ".join(part for part in (self.current, working) if part), live=True))

    def _unit_rows(self) -> list[str]:
        """Component bars shared by ticker and model callbacks; caller holds the console lock."""
        spin = self.st(SPINNER[self.frame % len(SPINNER)], "accent")
        return [
            f"{'':10}{spin} {name[: self.UNIT_NAME]:<{self.UNIT_NAME}}  "
            f"{self.st.bar(self._unit_progress(unit), 100, self.BAR_WIDTH)}  {self._unit_label(unit)}"
            for name, unit in self.units.items()
        ]

    @classmethod
    def planned_phases(cls, *, abuse_cases: bool) -> list[str]:
        """The phases a run executes, in order; skipped abuse cases drop their phase."""
        return [name for name in cls.WEIGHTS if abuse_cases or name != "Abuse cases"]

    def plan_phases(self, *, abuse_cases: bool) -> None:
        """Number the phases this run will execute; skipped abuse cases shorten the count."""
        self.plan = self.planned_phases(abuse_cases=abuse_cases)

    def plan_components(self, count: int) -> None:
        """Scale Controls and STRIDE to the run's components; RUN then shows a share."""
        self.components = max(1, count)
        # Recomputed with the scaled weights; the old share assumed nine components.
        self.done = 0.0
        if self.phase:
            self._advance(self.fraction)

    def _stamp(self, now: float) -> str:
        return time.strftime("%H:%M:%S", time.localtime(now))

    def write(self, text: str, now: float | None = None) -> None:
        now = self.clock() if now is None else now
        self.last = now
        # Heartbeat threads and the ticker write too; a line must not split a redraw.
        with _AssessmentConsole._lock:
            self.clear_status()
            self._out(f"{self.st(self._stamp(now), 'muted')}  {text}" if text else "")

    @staticmethod
    def _line(text: str) -> None:
        # One write per line: with the newline written apart, a follower such as
        # `tail -F` can see a row while its wrapped detail line is still open.
        sys.stderr.write(text + "\n")
        sys.stderr.flush()

    # Grid event -> the progress file's event.
    EVENTS = {
        "start": "phase_start",
        "done": "phase_done",
        "✓": "component_done",
        "·": "progress",
        "⚠": "warning",
        "↻": "correction",
    }

    def record(self, event: str, detail: str = "", now: float | None = None) -> None:
        """One grid row on the console and, field by field, in the progress file.

        A warning never ends the run; what ends it is the progress file's ``end``.
        """
        now = self.clock() if now is None else now
        self.write(self._row(event, detail, now), now)
        share, elapsed, left = self._run_fields(now)
        phase = self.phase or ""
        _AssessmentProgress.emit(
            self.EVENTS[event],
            time=self._stamp(now),
            phase=phase,
            number=self.plan.index(phase) + 1 if phase in self.plan else None,
            total=len(self.plan),
            progress=share,
            elapsed=elapsed,
            left=left,
            detail=detail,
        )

    def notice(self, text: str) -> None:
        """A line that needs attention, in the grid of the current phase."""
        self.record("⚠", text)

    @staticmethod
    def clear_status() -> None:
        """Remove the in-place status lines before any permanent line is written."""
        with _AssessmentConsole._lock:
            if _AssessmentConsole.status_shown:
                sys.stderr.write(_AssessmentConsole._clear_sequence())
                sys.stderr.flush()
                _AssessmentConsole.status_shown = False
                _AssessmentConsole.status_lines = 0

    @staticmethod
    def _clear_sequence() -> str:
        """The cursor stands on the last status line; clear it and each one above."""
        if not _AssessmentConsole.status_shown:
            return ""
        return "\r\033[K" + "\033[1A\033[K" * (_AssessmentConsole.status_lines - 1)

    # --width: the widest line the console writes, on a terminal and off it.
    max_columns: int | None = None

    @staticmethod
    def columns() -> int:
        """Columns a line may use: the terminal's, at most --width; --width alone off a terminal."""
        columns = shutil.get_terminal_size().columns
        limit = _AssessmentConsole.max_columns
        if limit is None:
            return columns
        return min(columns, limit) if sys.stderr.isatty() else limit

    @staticmethod
    def fit(text: str, indent: str = "  ") -> str:
        """`text` wrapped at --width, continuing under `indent`; unchanged without --width."""
        if _AssessmentConsole.max_columns is None:
            return text
        width = _AssessmentConsole.columns() - 1
        return "\n".join(textwrap.wrap(text, width, subsequent_indent=indent, break_on_hyphens=False)) or text

    # Shared, so the command-line entry can clear a status line before its last message.
    status_shown = False
    status_lines = 0
    # A status redraw: begin a synchronized update, hide the cursor, return to
    # the line start; then show the cursor and end the update. Terminals
    # without synchronized updates ignore the mode.
    FRAME_OPEN = "\033[?2026h\033[?25l\r"
    FRAME_CLOSE = "\033[?25h\033[?2026l"
    _lock = threading.RLock()
    _stopped = threading.Event()

    def _status(self, text: str, above: list[str] | None = None) -> None:
        """Redraw the complete live area, retaining component bars on every update."""
        if not self.live:
            return
        with _AssessmentConsole._lock:
            if above is None:
                above = self._unit_rows()
            lines = [*above, f"{self.st(self._stamp(self.clock()), 'muted')}  {text}"]
            # A wrapped status line would survive the next clear as a stray row.
            # Measured without colour codes; a line that must be cut loses its colour.
            width = self.columns() - 1
            for index, line in enumerate(lines):
                if len(ANSI_RE.sub("", line)) > width:
                    lines[index] = ANSI_RE.sub("", line)[: max(width - 1, 0)] + "…"
            # Overwrite in place instead of clearing first: a cleared line is
            # painted empty between ticks (Windows Terminal via ConPTY does so
            # even within one write), and the area flickers. Each line clears
            # only its own tail, `\033[J` the rows a shorter area leaves below.
            # The frame is a synchronized update with a hidden cursor, so the
            # terminal never shows it half drawn or the cursor moving.
            if self.prompting:
                return
            up = _AssessmentConsole.status_lines - 1 if _AssessmentConsole.status_shown else 0
            sys.stderr.write(
                _AssessmentConsole.FRAME_OPEN
                + (f"\033[{up}A" if up > 0 else "")
                + "\033[K\n".join(lines)
                + "\033[K\033[J"
                + _AssessmentConsole.FRAME_CLOSE
            )
            sys.stderr.flush()
            _AssessmentConsole.status_shown = True
            _AssessmentConsole.status_lines = len(lines)

    def _weight(self, phase: str) -> float:
        if self.components and phase in self.PER_COMPONENT:
            return self.PER_COMPONENT[phase] * self.components
        return self.WEIGHTS[phase]

    def _advance(self, fraction: float) -> None:
        """Record ``fraction`` of the current phase as finished."""
        self.fraction = max(self.fraction, min(fraction, 1.0))
        plan = self.plan if self.phase in self.plan else [*self.plan, self.phase]
        before = sum(self._weight(name) for name in plan[: plan.index(self.phase)])
        total = sum(self._weight(name) for name in plan)
        self.done = max(self.done, (before + self._weight(self.phase) * self.fraction) / total)

    def _expected_total(self) -> float:
        """Seconds the planned phases take at the nominal speed, scaled to the component count.

        Used until a component has finished and the run's own speed is known.
        """
        plan = self.plan if self.phase in self.plan else [*self.plan, self.phase]
        return self.NOMINAL_SECONDS * sum(self._weight(name) for name in plan) / self.NOMINAL_WEIGHT

    def _measured(self) -> bool:
        """Whether a threat-analysis component has finished.

        The earlier phases are mostly deterministic scans whose duration
        follows file count and host load, not model speed; extrapolated
        from them, the remaining time overstated a Juice Shop run twofold.
        """
        key = "Threat analysis"
        if self.phase not in self.plan or key not in self.plan:
            return False
        here, there = self.plan.index(self.phase), self.plan.index(key)
        return here > there or (here == there and self.fraction > 0)

    def continue_from(self, seconds: int) -> None:
        """Count ELAPSED on from the working time of the earlier attempts a resumed run continues."""
        self.run_started = self.clock() - seconds

    def _run(self, now: float) -> str:
        """The run columns: finished share, elapsed time, and the remaining time at the measured speed."""
        share, elapsed, left = self._run_fields(now)
        return f"{share:>8}  {elapsed:>7}  {left:>6}"

    def _run_fields(self, now: float) -> tuple[str, str, str]:
        elapsed, left = now - self.run_started, ""
        if self.done >= 1:
            share = "100%"
        else:
            share = f"~{min(99, round(100 * self.done))}%" if self.components else "planning"
            if self.done > 0 and self._measured():
                left = "~" + _elapsed(elapsed * (1 - self.done) / self.done)
            else:
                left = "~" + _elapsed(self._expected_total() * (1 - self.done))
        return share, _elapsed(elapsed), left

    def _row(self, event: str, detail: str = "", now: float | None = None, live: bool = False) -> str:
        """One grid row; ``live`` marks the terminal's status line (spinner and bar)."""
        now = self.clock() if now is None else now
        phase = self.phase or ""
        if phase:
            number = f"{self.plan.index(phase) + 1}/{len(self.plan)}" if phase in self.plan else "?"
            phase = f"{number} {phase}"
        run = self._run(now)
        if live:
            event = SPINNER[self.frame % len(SPINNER)]
            if self.components:
                detail = f"{self.st.bar(round(100 * self.done), 100, self.BAR_WIDTH)}  {detail}".rstrip()
        # Free text comes last, so a long detail never shifts a column.
        row = f"{phase:<{self._PHASE_WIDTH}}  {event:<{self._EVENT_WIDTH}}  {run}  {detail}"
        if not self.st.enabled:
            if self.max_columns is None:
                return row.rstrip()
            head = row[: len(row) - len(detail)]
            indent, pieces = self._wrap_detail(len(head), detail, now, live)
            return self._join(head, indent, pieces)
        # Colour wraps each padded column, so the grid keeps its widths.
        st, role = self.st, ("accent" if live else self.EVENT_ROLES.get(event))
        if event in ("start", "done"):
            phase_cell = st(f"{phase:<{self._PHASE_WIDTH}}", role, "bold")
        else:
            phase_cell = st(f"{phase:<{self._PHASE_WIDTH}}", "accent")
        event_cell = st(f"{event:<{self._EVENT_WIDTH}}", role or "muted")
        run_cell = st(run if detail else run.rstrip(), "muted")
        head = f"{phase_cell}  {event_cell}  {run_cell}  "
        # A long detail wraps under its own column instead of at the screen
        # edge; the status line is cut by `_status` instead.
        indent, pieces = self._wrap_detail(len(ANSI_RE.sub("", head)), detail, now, live)
        cells = [st(piece, "warn") if event == "⚠" and piece else piece for piece in pieces]
        return self._join(head, indent, cells)

    def _wrap_detail(self, head: int, detail: str, now: float, live: bool) -> tuple[int, list[str]]:
        """(indent, pieces) of a detail after a `head` columns wide grid head.

        A long detail continues under its own column. Where --width leaves that
        column too narrow, the detail starts on the next line after the time stamp.
        """
        indent = len(self._stamp(now)) + 2 + head
        fit = self.columns() - 1 - indent
        if live or len(detail) <= fit:
            return indent, [detail]
        if fit >= 20:
            return indent, textwrap.wrap(detail, fit, break_on_hyphens=False)
        if self.max_columns is None:
            return indent, [detail]
        indent = len(self._stamp(now)) + 2
        return indent, ["", *textwrap.wrap(detail, self.columns() - 1 - indent, break_on_hyphens=False)]

    @staticmethod
    def _join(head: str, indent: int, pieces: list[str]) -> str:
        lines = [head + pieces[0], *(" " * indent + piece for piece in pieces[1:])]
        return "\n".join(line.rstrip() for line in lines)

    def _header(self) -> None:
        if not self.headed:
            self.headed = True
            self.clear_status()
            self._out(
                self.st(
                    f"{'TIME':<8}  {'PHASE':<{self._PHASE_WIDTH}}  {'EVENT':<{self._EVENT_WIDTH}}  "
                    f"{'PROGRESS':>8}  {'ELAPSED':>7}  {'LEFT':>6}  DETAIL",
                    "muted",
                    "bold",
                )
            )

    def _heartbeat(self, now: float, extra: str = "") -> None:
        """Off a terminal: a progress line after a change, or as a liveness sign in a quiet stretch."""
        if not self.phase:
            return
        key = (self.current, round(100 * self.done))
        quiet = now - self.last
        if quiet >= self.HEARTBEAT_SECONDS or (quiet >= self.PROGRESS_SECONDS and key != self.shown):
            self.shown = key
            self.record("·", " · ".join(part for part in (self.current, extra) if part), now)

    def facts(self, title: str | None, rows: list[tuple[str, str]], *, sectioned: bool = False) -> None:
        """Run facts as ``Key : value`` rows, the single-repository wrapper's header format."""
        st = self.st
        if title:
            self.write("")
            if st.enabled:
                # The terminal gets the logo; its last line carries the title's mode.
                version = plugin_version()
                mode = title.partition(" — ")[2] or title
                with _AssessmentConsole._lock:
                    self.clear_status()
                    for line in logo(st, f"v{version} · {mode}" if version else mode, self.columns() - 1):
                        self._out(line)
                self.write("")
            elif self.max_columns:
                # The title carries the header's one time stamp; under --width it
                # wraps instead of being cut at the panel edge.
                first, *rest = textwrap.wrap(
                    f"▶ {title}", self.columns() - 1 - 10, subsequent_indent="  ", break_on_hyphens=False
                )
                self.write(first)
                for line in rest:
                    self._unstamped(" " * 10 + line)
            else:
                self.write(f"▶ {title}")
        width = max([11, *(len(key) for key, _ in rows)])
        # Facts share the title's moment, so they carry no time stamp of their
        # own. On a terminal a long value wraps flush under its own column
        # instead of at the screen edge; key and separators take the rest.
        indent = "    " if sectioned else "  "
        fit = self.columns() - 1 - (len(indent) + width + 2) if st.enabled or self.max_columns else 0
        groups = {"": rows}
        if sectioned:
            groups = {"Run": [], "Scope": [], "Workflow & results": []}
            for key, value in rows:
                section = (
                    "Scope"
                    if key in ("Focus", "Abuse cases", "Coverage", "Excludes", "Trust mode")
                    else "Workflow & results"
                    if key in ("Pipeline", "Artifacts")
                    else "Run"
                )
                groups[section].append((key, value))
        for section, entries in groups.items():
            if not entries:
                continue
            if section:
                if section != "Run":
                    self._unstamped("")
                self._unstamped(st(f"  {section}", "bold"))
            for key, value in entries:
                lines: list[str] = []
                for part in value.split("\n"):
                    if fit > 20 and len(part) > fit:
                        pieces = textwrap.wrap(part, fit, break_on_hyphens=False)
                    else:
                        pieces = [part]
                    lines.append(self._fact(key, pieces[0]))
                    lines.extend(st(piece, "muted") for piece in pieces[1:])
                first, *more = lines
                self._unstamped(f"{indent}{st(f'{key:<{width}}:', 'muted')} {first}")
                for line in more:
                    self._unstamped(f"{indent}{'':<{width}}  {line}")
        self.write("")

    def preflight(self, checks) -> None:
        """Completed start checks as a Preflight phase in the grid, before the first phase.

        Console only: the checks finished before the run, so no progress event follows.
        """
        if not checks:
            return
        self._header()
        now = self.clock()
        name = f"{'Preflight':<{self._PHASE_WIDTH}}"
        blank = f"{'':>8}  {'':>7}  {'':>6}"  # The empty PROGRESS, ELAPSED and LEFT columns.
        for symbol, label, message in checks:
            detail = f"{label}: {message}"
            event = f"{symbol:<{self._EVENT_WIDTH}}"
            head = f"{self.st(name, 'accent')}  {self.st(event, self.EVENT_ROLES.get(symbol) or 'muted')}  {blank}  "
            if not self.st.enabled and self.max_columns is None:
                indent, pieces = 0, [detail]
            else:
                indent, pieces = self._wrap_detail(len(ANSI_RE.sub("", head)), detail, now, False)
            self.write(self._join(head, indent, pieces), now)

    def _unstamped(self, text: str) -> None:
        """A permanent line without the time column, for the run header."""
        self.last = self.clock()
        with _AssessmentConsole._lock:
            self.clear_status()
            self._out(text)

    # Header facts whose leading value is coloured; a trailing "(…)" is context.
    FACT_ROLES = {
        "Repository": "accent",
        "Repositories": "accent",
        "Output": "accent",
        "Models": "agent",
        "Depth": "accent",
    }

    def _fact(self, key: str, line: str) -> str:
        if not self.st.enabled:
            return line
        if key == "Trust mode":
            role = "ok" if line.startswith("untrusted") else "warn" if line.startswith("trusted") else "muted"
            return self.st(line, role)
        if key == "Models":
            # The compact lineup joins models on one line; each model is coloured.
            return self.st(" · ", "muted").join(self._fact("Model", model) for model in line.split(" · "))
        head, sep, tail = line.partition(" (")
        role = self.FACT_ROLES.get("Models" if key == "Model" else key, "bold")
        return self.st(head, role) + self.st(sep + tail, "muted")

    def step(self, text: str) -> None:
        if text.startswith("Coverage gap: "):
            self.notice(text)
            return
        if text.startswith("Review coverage: "):
            detail = text.removeprefix("Review coverage: ")
            label = detail.partition(":")[0]
            self.review_coverage.setdefault(self.phase, {})[label] = detail
            self.record("·", detail)
            return
        if text.startswith(self.RESULT):
            phase, _, result = text[len(self.RESULT) :].partition(": ")
            self.results[phase] = result
            return
        # Steps name repository components; only printable text reaches the status line.
        self.activity = "".join(char if char.isprintable() else "?" for char in text)[: self._NAME_MAX]
        self.activity_started = time.monotonic()
        prefix, phase = next(((p, name) for p, name in self.PHASES if text.startswith(p)), (None, None))
        if phase is None:
            # Before the first phase a plain line; inside a phase a progress line of it.
            if self.phase:
                self.record("·", text)
            else:
                self.write(text)
            return
        now = self.clock()
        position = self._POSITION.search(text)
        if phase != self.phase:
            self.close(now)
            self.phase, self.started, self.finished_jobs = phase, now, 0
            self.current, self.count, self.positioned, self.parts = "", None, False, {}
            self.units, self.units_done = {}, 0
            self.corrections = Counter()
            self.fraction = 0.0
            self._advance(0.0)
            scope = _count_noun(int(position[2]), self.NOUNS[prefix]) if position and prefix in self.NOUNS else ""
            self._header()
            self.record("start", scope, now)
            self.shown = (self.current, round(100 * self.done))
            if self.on_phase:
                self.on_phase()
        if prefix in self.UNIT_STEPS:
            self._unit_step(prefix, text, position, now)
            return
        if position:
            # Subjects already finished in this phase, so the share never runs ahead.
            self.positioned = True
            self._advance((int(position[1]) - 1) / max(int(position[2]), 1))
            if prefix in self.NOUNS:
                self.count = (max(int(position[2]), self.count[0] if self.count else 0), self.NOUNS[prefix])
        if prefix not in self.SUBJECTS:
            if self.verbose:
                self.record("·", text, now)
            return
        # A crossing's ID is a signal hash, not a name a reader recognizes.
        name = "" if prefix == "Reviewing trust crossing" else self._POSITION.sub("", text[len(prefix) :].lstrip(": "))
        # No terminal control sequence from a name reaches the console.
        name = "".join(char if char.isprintable() else "?" for char in name)
        if len(name) > self._NAME_MAX:
            name = name[: self._NAME_MAX - 1].rstrip() + "…"
        noun = self.NOUNS.get(prefix, "")
        counter = f"{noun} {position[1]}/{position[2]}" if noun and position else noun
        self.parts = {}
        self.current = " · ".join(part for part in (counter, name) if part)
        if self.verbose or prefix in self.LISTED:
            self.record("·", self.current, now)
            self.shown = (self.current, round(100 * self.done))
        elif self.live:
            self._status(self._row("·", self.current, now, live=True))
        else:
            self._heartbeat(now)

    # Steps of a component analyzed concurrently with others (MR-16): its
    # start, each finished STRIDE job, its evidence review and its end.
    UNIT_STEPS = (
        "Analyzing all STRIDE categories",
        "Finished STRIDE job",
        "Independently verifying evidence",
        "Analyzed component",
    )
    UNIT_NAME = 26

    def _unit_step(self, prefix: str, text: str, position, now: float) -> None:
        """Track one concurrently analyzed component; the share follows finished work, not starts."""
        name = self._POSITION.sub("", text[len(prefix) :].lstrip(": "))
        name = "".join(char if char.isprintable() else "?" for char in name)[: self._NAME_MAX]
        with _AssessmentConsole._lock:
            if prefix == "Analyzing all STRIDE categories":
                self.positioned = True
                if position:
                    self.count = (max(int(position[2]), self.count[0] if self.count else 0), "component")
                self.units[name] = {"done": 0, "total": None, "stage": "STRIDE", "started": now}
                line = f"component {position[1]}/{position[2]} · {name}" if position else name
                if not self.live:
                    self.record("·", line, now)
            elif prefix == "Finished STRIDE job":
                unit = self.units.get(name)
                if unit is not None and position:
                    unit["done"], unit["total"] = int(position[1]), int(position[2])
            elif prefix == "Independently verifying evidence":
                if name in self.units:
                    self.units[name]["stage"] = "review"
            finished = None
            if prefix == "Analyzed component":
                unit = self.units.pop(name, None)
                self.units_done += 1
                finished = name + (f" · {_duration(now - unit['started'])}" if unit else "")
            total = self.count[0] if self.count else 0
            if total:
                running = sum(self._unit_progress(unit) / 100 for unit in self.units.values())
                self._advance((self.units_done + running) / total)
                # Under concurrency no single component is current; the bars name the running ones.
                self.current = f"{self.units_done}/{total} components done"
            if finished is not None:
                # Counts completions, so it names no start slot such as a start line's "component 4/9".
                # Its own event, so `done` marks only a phase's end.
                done = f"{self.units_done}/{total or '?'} components done · {finished}"
                self.record("✓", done, now)
            # A permanent line names the component; the heartbeat need not repeat the count.
            self.shown = (self.current, round(100 * self.done))

    @staticmethod
    def _unit_progress(unit: dict) -> int:
        """Percent of one component: its STRIDE jobs, then one share for the evidence review."""
        if unit["stage"] == "review":
            return 90
        if not unit["total"]:
            return 0
        return round(90 * unit["done"] / unit["total"])

    @staticmethod
    def _unit_label(unit: dict) -> str:
        if unit["stage"] == "review":
            return "evidence review"
        if not unit["total"]:
            return "STRIDE"
        return f"{unit['done']}/{unit['total']} STRIDE jobs"

    def call(self, text: str, role: str | None = None, model: str | None = None) -> None:
        """Show missing updates and timeouts; show every model-call line with --verbose."""
        context = ""
        identity = ""
        if text.startswith("[job-") and "] " in text:
            context, _, text = text.partition("] ")
            identity = context
            context = context + "] " if getattr(self, "verbose", False) else ""
        label = self.ROLE_LABELS.get(role, (role or "").replace("_", " "))
        who = context + (f"{label} [{model}]: " if role and model else (f"{label}: " if role else ""))
        call_key = identity + "|" + (role or "") + "|" + (model or "")
        if "no model activity" in text or text.startswith(("model call stopped", "host connection interrupted")):
            self.record("⚠", f"{who}{text}")
            return
        if "no progress update for" in text or "intermediate activity is unavailable" in text:
            # The ticker already renders the current call's age and state in
            # place. Plain logs retain one notice until the call changes state.
            kind = "silent" if "no progress update for" in text else "unavailable"
            with _AssessmentConsole._lock:
                if not self.live and (call_key, kind) not in self._call_notices:
                    self.record("·", f"{who}{text}")
                self._call_notices.add((call_key, kind))
            return
        with _AssessmentConsole._lock:
            self._call_notices = {notice for notice in self._call_notices if notice[0] != call_key}
        if text.startswith("answer rejected"):
            # MR-17: a correction repairs itself; the phase's done line counts it,
            # and only --verbose names each reason.
            with _AssessmentConsole._lock:
                self.corrections[label or "model"] += 1
                self.correcting.add(role)
            if self.verbose:
                self.record("↻", f"{who}{text}")
            return
        now = self.clock()
        finished = re.fullmatch(r"result: .* \((\d+) s\)", text)
        if finished and self.phase and not self.positioned:
            # Phases without numbered subjects advance by each finished job,
            # approaching but never reaching the phase's end share.
            self.finished_jobs += 1
            self._advance(self.finished_jobs / (self.finished_jobs + 1))
        if self.verbose:
            if finished:
                if role in self.correcting:
                    self.correcting.discard(role)
                    part = " (corrected)"
                else:
                    # A subject's second job of one role is a further batch or part.
                    self.parts[role] = self.parts.get(role, 0) + 1
                    part = f" (part {self.parts[role]})" if self.parts[role] > 1 else ""
                answered = f"{who.rstrip(': ') or 'model call'}{part} answered — {_duration(int(finished[1]))}"
                self.record("·", answered, now)
            else:
                self.record("·", f"{who}{text}", now)
            return
        status = re.sub(r"^\d+ min: ", "", text) if re.match(r"\d+ min: ", text) else ""
        # The phase column already names a role of the same name.
        extra = status if not status or label.lower() == (self.phase or "").lower() else f"{label}: {status}"
        if self.live:
            if self.phase:
                self._status(self._row("·", " · ".join(part for part in (self.current, extra) if part), now, live=True))
            return
        self._heartbeat(now, extra)

    def close(self, now: float | None = None) -> None:
        if self.phase:
            now = self.clock() if now is None else now
            produced = [_duration(now - self.started)]
            coverage = self.review_coverage.get(self.phase, {})
            if self.count and "abuse-case verification" not in coverage:
                produced.append(_count_noun(*self.count))
            if self.results.get(self.phase):
                produced.append(self.results[self.phase])
            produced.extend(coverage.values())
            if self.corrections:
                total = sum(self.corrections.values())
                roles = ", ".join(f"{role} {count}" for role, count in sorted(self.corrections.items()))
                produced.append(f"{_count_noun(total, 'answer')} corrected ({roles})")
            self._advance(1.0)
            if self.phase == self.plan[-1]:
                self.done = 1.0
            self.record("done", " · ".join(produced), now)
        self.phase = None
