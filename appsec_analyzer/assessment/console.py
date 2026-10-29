"""Assessment progress feed and terminal presentation."""

from __future__ import annotations

import functools
import json
import os
import re
import shutil
import subprocess
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


def _tokens(count: int) -> str:
    """A token count for a result line: ``850``, ``42k``, ``1.3M``."""
    if count < 1000:
        return str(count)
    return f"{count / 1000:.0f}k" if count < 1_000_000 else f"{count / 1_000_000:.1f}M"


@functools.lru_cache(maxsize=1)
def _claude_cli_bills_api() -> bool:
    """Whether the Claude CLI authenticates with an API key or a cloud provider, not a subscription login.

    The CLI knows where its credentials come from (environment, ``settings.json``, ``apiKeyHelper``,
    Console login, Bedrock, Vertex), so ask it instead of inspecting only this process's environment.
    """
    executable = os.environ.get("APPSEC_CLAUDE_EXECUTABLE") or "claude"
    try:
        result = subprocess.run([executable, "auth", "status"], capture_output=True, timeout=10, check=False)
        status = json.loads(result.stdout[:8192])
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return False
    if not isinstance(status, dict):
        return False
    return bool(status.get("apiKeySource")) or status.get("apiProvider") not in (None, "firstParty")


_CLAUDE_CLOUD_PROVIDERS = {"bedrock": "Amazon Bedrock", "vertex": "Google Vertex", "foundry": "Microsoft Foundry"}
_CLAUDE_CLOUD_SWITCH = re.compile(r"CLAUDE_CODE_USE_([A-Z0-9_]+)")
_CLAUDE_BASE_URL = re.compile(r"ANTHROPIC_(?:[A-Z0-9_]+_)?BASE_URL")


@functools.lru_cache(maxsize=1)
def _claude_cli_provider() -> str | None:
    """The cloud provider the Claude CLI reports for its login, or nothing for Anthropic directly."""
    executable = os.environ.get("APPSEC_CLAUDE_EXECUTABLE") or "claude"
    try:
        result = subprocess.run([executable, "auth", "status"], capture_output=True, timeout=10, check=False)
        status = json.loads(result.stdout[:8192])
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    provider = status.get("apiProvider") if isinstance(status, dict) else None
    return provider if isinstance(provider, str) and provider != "firstParty" else None


def claude_cli_route() -> str:
    """Where Claude CLI sends its requests, for the header's Host row: ``Claude CLI``, plus ``via …`` when it
    does not talk to Anthropic directly.

    The provider comes from the CLI itself, with any ``CLAUDE_CODE_USE_<PROVIDER>`` switch as fallback, and the
    gateway from any ``ANTHROPIC_*BASE_URL`` variable. A gateway is shown as
    its host name only, so a path, port or credential in the operator's URL never reaches the terminal.
    """
    from urllib.parse import urlsplit

    from appsec_analyzer.terminal import field

    environment = sorted(os.environ.items())
    provider = _claude_cli_provider() or next(
        (
            match[1].lower()
            for name, value in environment
            if (match := _CLAUDE_CLOUD_SWITCH.fullmatch(name)) and value.strip().lower() in ("1", "true")
        ),
        None,
    )
    gateway = None
    for name, value in environment:
        if not _CLAUDE_BASE_URL.fullmatch(name):
            continue
        try:
            host = urlsplit(value.strip()).hostname
        except ValueError:
            continue
        if host and host != "api.anthropic.com":
            gateway = host
            break
    via = []
    if provider:
        via.append(_CLAUDE_CLOUD_PROVIDERS.get(provider) or field(provider))
    if gateway:
        via.append(f"gateway {field(gateway)}")
    return f"Claude CLI via {', '.join(via)}" if via else "Claude CLI"


def api_billing(adapter: str | None = None) -> bool:
    """Use the assessment header's existing provider and API-key selection."""
    if adapter in ("codex-cli", "copilot-cli"):
        return False
    if adapter in ("openai", "lite", "bedrock", "gateway"):
        return True
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return True
    return _claude_cli_bills_api()


def usd_at_api_prices(adapter: str | None = None) -> bool:
    """Whether a USD limit counts Claude subscription usage at the API prices Claude CLI reports."""
    return adapter not in ("codex-cli", "copilot-cli") and not api_billing(adapter)


def usage_text(before: dict, after: dict, total: bool = False, *, show_costs: bool | None = None) -> str:
    """What the model calls between two budget marks cost, or "" when none was paid for.

    The tokens come only when the hosts itemised every call of the step; a partial sum would read as the
    whole. An explicit cost request names unavailable amounts; otherwise a subscription run has no
    amount to show. ``total`` adds costs of results taken over from an earlier run.
    """
    calls = after["calls"] - before["calls"]
    if calls <= 0:
        return ""
    if show_costs is None:
        show_costs = after["usd"] is not None and before["usd"] is not None
    parts = []
    if show_costs:
        text = (
            "USD cost unavailable"
            if after["usd"] is None or before["usd"] is None
            else f"≈ USD {after['usd'] - before['usd']:.2f}"
        )
        if total and after.get("total_usd") is not None:
            text += f" (USD {after['total_usd']:.2f} in total)"
        parts.append(text)
    tokens = after["tokens"] - before["tokens"]
    if tokens > 0 and after["itemised"] - before["itemised"] == calls:
        parts.append(f"{_tokens(tokens)} tokens")
    return " · ".join(parts)


STOP_LABEL_WIDTH = 11
KEPT = ("Status", "finished steps are kept")
RESUME = "run the same command again with --resume"


def stop_message(headline: str, *rows: tuple[str, str]) -> str:
    """A run's stop as one block: a blank line, the headline, then labelled rows.

    ``⏸`` marks a stop that ``--resume`` continues and ``✗`` one to look into first.
    A long row wraps under its own text column, as under ``--width``.
    """
    indent = " " * (2 + STOP_LABEL_WIDTH + 2)
    lines = ["", headline]
    lines += [_AssessmentConsole.fit(f"  {label:<{STOP_LABEL_WIDTH}}  {text}", indent) for label, text in rows]
    return "\n".join(lines)


def model_failure_rows(error) -> list[tuple[str, str]]:
    """Rows for a rejected analysis, from job context only; technical IDs stay in diagnostics."""
    from runtime.assessment_diagnostics import safe_reason
    from runtime.assessment_host import ModelAnswerFailure

    if not isinstance(error, ModelAnswerFailure):
        return []
    job = getattr(error, "assessment_job", {})
    role = job.get("role")
    phase = {"stride_analyzer": "Threat analysis", "architecture_analyst": "Architecture"}.get(
        role, _AssessmentConsole.ROLE_LABELS.get(role, "Analysis")
    )
    reason = f"{phase} could not produce a valid result"
    label = safe_reason(job.get("label", ""))
    batch = re.search(r":(\d+)/(\d+)$", job.get("selector", ""))
    if label:
        reason += f" for {str(job.get('subject', 'Component')).lower()} {label}" + (
            f" (batch {batch[1]} of {batch[2]})" if batch else ""
        )
    if error.attempts:
        reason += f" after {_count_noun(error.attempts, 'attempt')}"
    rows = [("Reason", reason)]
    issues = getattr(error.rejection, "surface_issues", ())
    if issues:
        for issue in issues[:3]:
            location = safe_reason(f"{issue['file']}:{issue['line']}")
            why = (
                "the required source line was not read"
                if issue["reason"] == "unread"
                else "the source was read, but the model's decision cites a different source"
            )
            rows.append(("Detail", f"{location}: {why}"))
    elif error.rejection:
        rows.append(("Detail", safe_reason(str(error.rejection))))
    else:
        rows.append(("Detail", safe_reason(job.get("reason", str(error)))))
    rows += [KEPT, ("Continue", f"{RESUME}; if it stops the same way, read the diagnostics first")]
    diagnostics = getattr(error, "diagnostic_path", None)
    if diagnostics:
        rows.append(("Diagnostics", str(diagnostics)))
    return rows


class _AssessmentProgress:
    """The run's progress as JSON lines (``--progress-file``), for a follower such as a skill's monitor.

    The console grid is for people: padded columns and wrapped details. A
    follower reads named fields instead, one record per append, so it never
    parses columns or joins continuation lines. ``end`` is the last record of
    every run that opened the file, whatever ended it.
    """

    path: Path | None = None
    last_retry: tuple[str, float] | None = None
    # The run's parallel model jobs, which a rate-limit stop advises lowering.
    max_parallel: int | None = None
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
    for a component whose survey or verification finished, ``·`` for
    progress, and ``⚠`` (stalled or stopped model call, plugin change,
    verification job without a result) or
    ``↻`` (rejected answer) for lines that need attention. PROGRESS, ELAPSED
    and LEFT always describe the whole run. DETAIL describes the phase and
    comes last, so its length never shifts a column; a ``done`` line's
    detail starts with the phase's duration. In the threat analysis, DETAIL
    starts with a column naming the method a line belongs to: Scanners, Survey
    and, with verification, Verify. The run header explains the three; Survey
    and Verify each have a start and a done line of their own. A phase's
    start line names its scope, what the phase does and the agents that work
    in it with their models in parentheses (``(Sonnet 5.5)``). The threat
    analysis's start line names the methods the run header lists instead; the
    start lines of Survey and Verify name their agents' models.

    PROGRESS counts finished work. Once the component count is known
    (``plan_components``), Controls and STRIDE weigh per component. LEFT
    extrapolates the speed this run measured once a component has finished;
    before that it scales a nominal run time to the planned phases and
    components, so it changes as the run learns its size. Work taken over from
    an earlier run finishes in seconds, so its share and time stay out of the
    measured speed until a job of this attempt has advanced it. Before the component
    count is known PROGRESS says ``planning``. Time stamps and durations read
    one clock. A resumed run's ELAPSED shows this attempt's time and, in
    parentheses, the working time of all its attempts (``continue_from``); a
    new run that takes over an unfinished run adds that run's working time.
    When costs are shown, both add what all results cost so far to a phase's done line.

    Steps taken over from an earlier run's accepted jobs make no model call.
    A phase, and in the threat analysis each method, says so once when its
    first job is taken over (``taken_over``). Such a component's line shows no
    duration; the done lines of a phase, the survey and verification say how
    much came from the earlier run.

    Off a terminal (CI, logs) a progress line follows a change after
    ``PROGRESS_SECONDS`` and comes at the latest after ``HEARTBEAT_SECONDS``;
    a terminal gets one progress line rewritten in place instead, redrawn
    every ``TICK_SECONDS`` with a spinner, a progress bar, each running model
    call's age and activity, or the running controller step's age. On a
    terminal the columns carry colour (``renderers/term_style``); an injected
    writer is a log and stays plain. Each STRIDE component and each
    verified abuse case gets its own line in both. ``--verbose`` adds every
    step and model call as progress lines and keeps the terminal's status
    line; ``--quiet`` prints nothing. ``show_costs`` controls monetary amounts;
    available token counts remain visible when costs are hidden.
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
        "stride_analyzer": "survey",
        "test_case_investigator": "verification",
        "open_reviewer": "open review",
        "evidence_verifier": "evidence review",
        "threat_merger": "merge review",
        "finding_combiner": "text combination",
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
        ("Scanners · ", "Threat analysis"),
        ("Surveying component", "Threat analysis"),
        ("Finished survey job", "Threat analysis"),
        ("Independently verifying evidence", "Threat analysis"),
        ("Analyzed component", "Threat analysis"),
        ("Reviewing merge candidates", "Consolidation"),
        ("Reviewing the evidence of verification findings", "Consolidation"),
        ("Combining the texts of", "Consolidation"),
        ("Merge · ", "Consolidation"),
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
        ("Abuse cases to verify", "Abuse cases"),
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
        "Surveying component",
        "Reviewing findings as architect",
        "Reviewing promoted findings as architect",
        "Verifying abuse case",
        "Stage 2:",
    )
    # Subjects that also get a permanent line each, so the run's console
    # names every discovered repository and analyzed component. The abuse
    # cases run concurrently and are named once, in the list of "Abuse cases to verify".
    LISTED = ("Discovering repository", "Surveying component")
    # Steps that state a result and start their phase if it has not started; each gets a permanent line as written.
    STATED = ("Merge · ", "Scanners · ")
    # Listed names come from repository files and model output.
    _NAME_MAX = 100
    # What a phase's subjects are, for progress lines and the done line's count.
    NOUNS = {
        "Discovering repository": "repository",
        "Analyzing local architecture": "repository",
        "Reviewing trust crossing batch": "batch",
        "Reviewing trust crossing": "crossing",
        "Assessing controls": "component",
        "Surveying component": "component",
        "Reviewing findings as architect": "architect review",
        "Reviewing promoted findings as architect": "architect review",
        "Verifying abuse case": "abuse case",
        "Stage 2:": "report section",
    }
    # What each phase does, for its start line; the agents' models follow it. The threat analysis names its
    # methods instead (`_description`), and each method's start line names its models.
    PHASE_DESCRIPTIONS = {
        "Reconnaissance": "maps structure, technology and security-relevant code",
        "Architecture": "derives components and data flows",
        "Trust boundaries": "checks where data crosses between components",
        "Controls": "assesses the security controls",
        "Consolidation": "merges duplicate findings, then reviews and ranks them",
        "Abuse cases": "derives and verifies business abuse cases",
        "Finalization": "builds the report and runs the quality checks",
    }
    # Prefix of a phase's result step: "<RESULT><phase>: <what it produced>".
    RESULT = "Phase result: "
    # Suffix of a component's last step when every job it needed was reused.
    REUSED = " · reused"
    _POSITION = re.compile(r"\s*\((\d+)/(\d+)\)$")
    # Expected minutes per phase of a nine-component run with four components at
    # once, measured on the quick and standard Juice Shop runs of 2026-10-26
    # (22 and 41 minutes); threat analysis includes the source scanners and
    # evidence reviews. Controls and threat analysis scale with the component
    # count, the other phases stay fixed. Survey and verification on Opus are
    # not measured yet. A display estimate only: the remaining time follows the
    # speed the run measures once a threat analysis component has finished.
    WEIGHTS = {
        "Reconnaissance": 1.5,
        "Architecture": 2,
        "Trust boundaries": 1.3,
        "Controls": 1.2,
        "Threat analysis": 11.5,
        "Consolidation": 2.5,
        "Abuse cases": 1.2,
        "Finalization": 7,
    }
    PER_COMPONENT = {"Controls": 1.2 / 9, "Threat analysis": 11.5 / 9}
    # REQ-040: a verification job adds half a component's survey to threat
    # analysis (Juice Shop, 2026-10-26: the survey of nine components took about
    # 11.5 minutes, 19 verification jobs about 12.5).
    VERIFY_JOB_WEIGHT = PER_COMPONENT["Threat analysis"] / 2
    # Finalization follows the depth's quality checks: 3.2 minutes with the core
    # checks of quick, 7 with the full checks of standard. The extended checks of
    # thorough are not measured yet and count as full.
    FINALIZATION = {"core": 3.2, "full": 7, "extended": 7}
    # The architect review adds to consolidation (Juice Shop thorough,
    # 2026-10-27: 11 jobs in about 7 minutes before the abuse cases started).
    ARCHITECT_REVIEW = 7
    # How each threat analysis method examines the code, for the run header (REQ-040). Survey and Verify are
    # separate approaches, not steps that build on each other; the scanners' hits are where both start.
    METHODS = {
        "Scanners": "deterministic code and configuration checks, no model calls; hits feed {starts}",
        "Survey": "STRIDE-based review per component: entry points, outbound calls, scanner hits",
        "Verify": "fixed verification catalog",
    }
    # Width of the method column that starts DETAIL in the threat analysis.
    _METHOD_WIDTH = max(len(name) for name in METHODS)
    # The plan comes before the survey, the start after it; both name the components and end with the job count.
    # Only the start is shown: the plan only weighs the phase.
    _VERIFY_PLAN = re.compile(r"Verify (?:planned|start) · (\d+) components?(?: for | · ).* · (\d+) jobs?$")
    _VERIFY_START = "Verify start · "
    # The start's components and the rest after its aspects, which the run header already names.
    _VERIFY_SHOWN = re.compile(
        r"Verify start · (\d+ components?)(?: for [^·]*?| · [A-Za-z][\w-]*(?:, [A-Za-z][\w-]*)*)?(?= · |$)(.*)$"
    )
    # The end, then one line per aspect; the console adds the step's duration and cost.
    _VERIFY_DONE = "Verify done"
    # What a component's survey found, at the end of its name.
    _FOUND = re.compile(r" · (\d+ findings?)$")
    # What the survey found, said when it ends; the console adds its duration and component count.
    _SURVEY_DONE = "Survey done · "
    # A component's jobs are its parts; the console shows one step per component.
    _VERIFY_JOB = re.compile(
        r"(Verifying|Finished verifying) component (\d+)/\d+, part \d+/(\d+), (\S+): (.*?)"
        r"(?: · no result \((\w+)\))?$"
    )
    _BUDGET_SKIP = re.compile(
        r"Coverage gap: (.+?)(?: \([A-Z][A-Z0-9-]{1,79}\))? job skipped: budget reserved for required completion work"
    )
    _NAME_WIDTH = max(len(name) for name in WEIGHTS)
    # "n/N " before the phase name, then the event column.
    _PHASE_WIDTH = _NAME_WIDTH + 4
    _EVENT_WIDTH = 5

    def __init__(self, verbose: bool, write=None, live: bool | None = None, clock=time.time, *, show_costs=True):
        self.verbose = verbose
        self.show_costs = show_costs
        self._out = write or self._line
        # The in-place status line needs a terminal; an injected writer is a log.
        self.live = (write is None and sys.stderr.isatty()) if live is None else live
        self.st = Style.for_stream(sys.stderr) if write is None else Style(False)
        self.frame = 0
        # One clock for time stamps and durations, so each line's figures agree.
        self.clock = clock
        self.plan = list(self.WEIGHTS)
        # The depth's quality checks and whether it runs the architect review; they weigh finalization and consolidation.
        self.qa_depth, self.architect_review = "full", False
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
        # survey jobs and the current stage; and the components finished.
        self.units: dict[str, dict] = {}
        self.units_done = 0
        # Verification jobs after the survey, planned before it (REQ-040), and
        # the finished ones; the components they verify, the finished ones,
        # and each component's parts by its number.
        self.verify_jobs, self.verify_done = 0, 0
        self.verify_components, self.verify_components_done = 0, 0
        self.verify_running: dict[str, dict] = {}
        # Start times and durations of the threat analysis steps, Survey and Verify.
        self.steps: dict[str, float] = {}
        self.step_times: dict[str, float] = {}
        # The threat analysis method of the current lines, and the components each method took from the earlier run.
        self.method = ""
        self.method_reused: Counter = Counter()
        # The threat analysis methods the run header names, for the phase's start line.
        self.methods = ["Scanners", "Survey"]
        # (phase, method) pairs that already said a job was taken over from the earlier run.
        self.announced: set = set()
        # Corrected answers per role in the current phase (MR-17).
        self.corrections: Counter = Counter()
        # Budget-skipped optional jobs per role in the current phase: the first
        # gets a line, the done line counts the rest.
        self.budget_skips: Counter = Counter()
        self.results: dict[str, str] = {}
        self.review_coverage: dict[str, dict[str, str]] = {}
        self.headed, self.shown = False, None
        # Whether the Pre-run checks block stands open above the grid.
        self.checked = False
        # Called once a phase has started, e.g. to report a plugin change at once.
        self.on_phase = None
        # Jobs reused and run so far (AssessmentJobs.job_counts), and their
        # counts when the current phase started.
        self.job_counts = None
        self.phase_jobs = (0, 0)
        # The budget's usage mark (AssessmentBudget.usage_mark), and its value when the current phase and
        # each of its steps started; what a step cost is the difference of two marks.
        self.usage_mark = None
        self.phase_usage = None
        self.step_usage = {}
        self.run_started = self.last = self.clock()
        # The run's share and seconds that passed while it took over jobs, whether it does so now, and the job
        # counts and time of the last advance; LEFT leaves the taken-over work out of the measured speed.
        self.replayed_share, self.replayed_seconds, self.replaying = 0.0, 0.0, False
        self.advanced_jobs, self.advanced_at = (0, 0), self.run_started
        # Working seconds of the earlier attempts a resumed run continues, or of the unfinished run a new
        # run takes over (``continue_from``), and whether the run was resumed.
        self.worked_before, self.resumed = 0, False
        # Model calls in flight (_ReportedTransport registers itself) and the
        # last controller step with its start, for the terminal's status line.
        self.running: dict[int, Any] = {}
        # The (role, model) pairs of each phase's agents, named on the phase's start line.
        self.phase_models: dict[str, list[tuple[str, str]]] = {}
        self._call_notices: set[tuple[str, str]] = set()
        self.prompting = False
        self.activity, self.activity_started = "", time.monotonic()

    _MODEL_ID = re.compile(r"(?:claude-)?(haiku|sonnet|opus|fable)(?:-(\d+)(?:-(\d{1,2}))?)?(?:-\d{8})?")

    @staticmethod
    def short_model(model: str) -> str:
        """A model as the status lines name it: ``Sonnet 5.5`` for ``claude-sonnet-5-5``, ``Haiku`` for ``haiku``.

        An ID of another form is shown without its vendor prefix.
        """
        match = _AssessmentConsole._MODEL_ID.fullmatch(str(model))
        if not match:
            return str(model).removeprefix("claude-")
        family, major, minor = match.groups()
        return " ".join(part for part in (family.capitalize(), f"{major}.{minor}" if minor else major) if part)

    def _description(self, phase: str) -> str:
        """What a phase does, for its start line; the threat analysis names its methods: ``Scanners and Survey``."""
        if phase != "Threat analysis":
            return self.PHASE_DESCRIPTIONS.get(phase, "")
        *first, last = self.methods
        return f"{', '.join(first)} and {last}" if first else last

    def phase_agents(self, phase: str) -> str:
        """The models of a phase's or a threat analysis method's agents as its start line names them: ``(Sonnet 5.5)``.

        Roles on different models are named by role: ``(survey: Sonnet 5.5, evidence review: Haiku)``.
        """
        roles = self.phase_models.get(phase, [])
        models = list(dict.fromkeys(model for _, model in roles))
        if len(models) <= 1:
            return f"({models[0]})" if models else ""
        return (
            "("
            + ", ".join(
                f"{' + '.join(self.ROLE_LABELS.get(role, role) for role, other in roles if other == model)}: {model}"
                for model in models
            )
            + ")"
        )

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
        rows = [
            f"{'':10}{spin} {name[: self.UNIT_NAME]:<{self.UNIT_NAME}}  "
            f"{self.st.bar(self._unit_progress(unit), 100, self.BAR_WIDTH)}  {self._unit_label(unit)}"
            for name, unit in self.units.items()
        ]
        # A component being verified shows its aspects at work and the share of its verification finished.
        rows += [
            f"{'':10}{spin} {unit['name'][: self.UNIT_NAME]:<{self.UNIT_NAME}}  "
            f"{self.st.bar(round(100 * unit['done'] / unit['total']), 100, self.BAR_WIDTH)}  "
            f"{', '.join(sorted(unit['active']))}"
            for unit in self.verify_running.values()
            if unit["running"]
        ]
        return rows

    @classmethod
    def planned_phases(cls, *, abuse_cases: bool) -> list[str]:
        """The phases a run executes, in order; skipped abuse cases drop their phase."""
        return [name for name in cls.WEIGHTS if abuse_cases or name != "Abuse cases"]

    def plan_phases(self, *, abuse_cases: bool, qa_depth: str = "full", architect_review: bool = False) -> None:
        """Number the phases this run will execute; skipped abuse cases shorten the count.

        The depth's quality checks and architect review weigh finalization and consolidation.
        """
        self.plan = self.planned_phases(abuse_cases=abuse_cases)
        self.qa_depth, self.architect_review = qa_depth, architect_review

    def plan_components(self, count: int) -> None:
        """Scale Controls and STRIDE to the run's components; RUN then shows a share."""
        self.components = max(1, count)
        # Recomputed with the scaled weights; the old share assumed nine components, and so did its replayed part.
        old, self.done = self.done, 0.0
        if self.phase:
            self.done = self._share()
        self.replayed_share = self.replayed_share * self.done / old if old else 0.0

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
        total = self._total(now)
        phase = self.phase or ""
        _AssessmentProgress.emit(
            self.EVENTS[event],
            time=self._stamp(now),
            phase=phase,
            number=self.plan.index(phase) + 1 if phase in self.plan else None,
            total=len(self.plan),
            progress=share,
            elapsed=elapsed,
            **({"elapsed_total": total} if total else {}),
            left=left,
            **({"method": self.method} if self.method and event not in ("start", "done") else {}),
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

    # The widest a terminal line gets without --width; longer lines are hard to read on a wide window.
    DEFAULT_COLUMNS = 140

    @staticmethod
    def wraps() -> bool:
        """Whether lines wrap: on a terminal, and off it only under --width."""
        return _AssessmentConsole.max_columns is not None or sys.stderr.isatty()

    @staticmethod
    def columns() -> int:
        """Columns a line may use: the terminal's, at most --width or 140; --width alone off a terminal."""
        columns = shutil.get_terminal_size().columns
        limit = _AssessmentConsole.max_columns
        if limit is None:
            return min(columns, _AssessmentConsole.DEFAULT_COLUMNS) if sys.stderr.isatty() else columns
        return min(columns, limit) if sys.stderr.isatty() else limit

    @staticmethod
    def fit(text: str, indent: str = "  ") -> str:
        """`text` wrapped at the line width, continuing under `indent`; unchanged off a terminal without --width."""
        if not _AssessmentConsole.wraps():
            return text
        width = _AssessmentConsole.columns() - 1
        return "\n".join(textwrap.wrap(text, width, subsequent_indent=indent, break_on_hyphens=False)) or text

    # Shared, so the command-line entry can clear a status line before its last message.
    status_shown = False
    status_lines = 0
    # A status redraw: begin a synchronized update, hide the cursor, return to
    # the line start; then return to the line start again, show the cursor and
    # end the update. Terminals without synchronized updates ignore the mode.
    # Left at the line end, the cursor took input the terminal echoes, such as
    # a key press, into the last column, and the terminal wrapped there: the
    # next redraw started a row lower and left the previous line behind. At
    # the line start an echoed character is overwritten by the next redraw.
    FRAME_OPEN = "\033[?2026h\033[?25l\r"
    FRAME_CLOSE = "\r\033[?25h\033[?2026l"
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
            weight = self.PER_COMPONENT[phase] * self.components
        elif phase == "Finalization":
            weight = self.FINALIZATION.get(self.qa_depth, self.WEIGHTS[phase])
        else:
            weight = self.WEIGHTS[phase]
        if phase == "Threat analysis":
            weight += self.verify_jobs * self.VERIFY_JOB_WEIGHT
        elif phase == "Consolidation" and self.architect_review:
            weight += self.ARCHITECT_REVIEW
        return weight

    def _survey_share(self) -> float:
        """The survey's part of the threat analysis; the verification jobs take the rest."""
        return 1 - self.verify_jobs * self.VERIFY_JOB_WEIGHT / self._weight("Threat analysis")

    def _survey_done(self, now: float, found: str = "") -> None:
        """The survey's done line: components, what it found, duration and cost, and what came from the earlier run."""
        self.step_times["Survey"] = now - self.steps["Survey"]
        took = _duration(self.step_times["Survey"]) + self._step_cost("Survey")
        earlier = self._earlier(self.method_reused["Survey"], self.units_done)
        counts = " · ".join([_count_noun(self.units_done, "component"), *([found] if found else [])])
        self.record("·", f"done · {counts} · {took}{earlier}", now)

    def _verify_step(self, text: str, now: float, reused: bool = False) -> bool:
        """Show verification as the second step of the threat analysis (REQ-040); False for other lines.

        The plan arrives before the survey, so the phase weighs the jobs from the
        start and the run's share never falls. Jobs run concurrently, so a job's
        start only names it, and its end advances the share. A component's jobs
        are its parts: its row comes when the last one ends, so a component
        checked in several jobs is still one step, marked reused when each part was.
        """
        with _AssessmentConsole._lock:
            if text.startswith(self._SURVEY_DONE) and "Survey" in self.steps:
                self._survey_done(now, text[len(self._SURVEY_DONE) :])
                return True
            if plan := self._VERIFY_PLAN.match(text):
                components, jobs = int(plan[1]), int(plan[2])
                # The job count only weighs the step; the line shows the components.
                text = text[: text.rindex(" · ")]
                self.verify_components = components
                if jobs != self.verify_jobs:
                    # The finished part keeps its weight in the larger phase.
                    weight = self._weight(self.phase)
                    self.verify_jobs = jobs
                    self.fraction *= weight / self._weight(self.phase)
                    self._advance(self.fraction)
                if text.startswith(self._VERIFY_START):
                    # The survey's own line, when it came, already ended its step.
                    if "Survey" in self.steps and "Survey" not in self.step_times:
                        self._survey_done(now)
                    self.steps["Verify"] = now
                    self._mark_step("Verify")
                    self.method = "Verify"
                    if "taken over" in text:
                        # The start already says so; its first taken-over job adds no line.
                        self.announced.add((self.phase, self.method))
                    self.current = f"0/{components} components done"
                    shown = self._VERIFY_SHOWN.match(text)
                    agents = f" {models}" if (models := self.phase_agents("Verify")) else ""
                    self.record("·", f"start · {shown[1]}{agents}{shown[2]}" if shown else text, now)
                self.shown = (self.current, round(100 * self.done))
                return True
            if text.startswith(self._VERIFY_DONE):
                rest = text[len(self._VERIFY_DONE) :]
                if "Verify" in self.steps:
                    self.step_times["Verify"] = now - self.steps["Verify"]
                    took = _duration(self.step_times["Verify"]) + self._step_cost("Verify")
                    earlier = self._earlier(self.method_reused["Verify"], self.verify_components_done)
                    rest = f" · {took}{earlier}{rest}"
                self.current = ""
                # The aspect lines that follow belong to verification too.
                self.method = "Verify"
                self.record("·", "done" + rest, now)
                return True
            job = self._VERIFY_JOB.match(text)
            if not job:
                return False
            started, number, total, aspect, name, cause = (
                job[1] == "Verifying",
                job[2],
                int(job[3]),
                job[4],
                job[5],
                job[6],
            )
            # Names come from repository files and model output.
            name = "".join(char if char.isprintable() else "?" for char in name)[: self._NAME_MAX]
            unit = self.verify_running.setdefault(
                number,
                {
                    "started": now,
                    "running": 0,
                    "done": 0,
                    "reused": 0,
                    "aspects": [],
                    "gaps": Counter(),
                    "name": name,
                    "total": total,
                    "active": Counter(),
                },
            )
            if aspect not in unit["aspects"]:
                unit["aspects"].append(aspect)
            if started:
                unit["running"] += 1
                unit["active"][aspect] += 1
            else:
                unit["running"] = max(0, unit["running"] - 1)
                unit["active"][aspect] -= 1
                if unit["active"][aspect] <= 0:
                    del unit["active"][aspect]
                unit["done"] += 1
                unit["reused"] += reused
                if cause:
                    unit["gaps"][cause] += 1
                self.verify_done += 1
                weight = self._weight(self.phase)
                self._advance(self._survey_share() + self.verify_done * self.VERIFY_JOB_WEIGHT / weight)
            finished = not started and unit["done"] >= total
            self.verify_components_done += finished
            position = f"{self.verify_components_done}/{max(self.verify_components, self.verify_components_done)}"
            running = sum(1 for row in self.verify_running.values() if row["running"])
            self.current = f"{position} components done" + (f" · {running} running" if running else "")
            if started:
                # The terminal shows running components on its status line; a log gets a row for each.
                if not self.live and unit["running"] + unit["done"] == 1:
                    self.record("·", f"component {number} started · {name}", now)
                return True
            if not finished:
                return True
            parts = [f"{position} {name}", ", ".join(unit["aspects"])]
            if gaps := unit["gaps"]:
                causes, missing = ", ".join(sorted(gaps)), sum(gaps.values())
                parts.append(
                    f"no result ({causes})" if total == 1 else f"{missing} of {total} parts without result ({causes})"
                )
            # A component taken from the earlier run took no time worth naming; the done line counts it.
            if unit["reused"] >= total:
                self.method_reused["Verify"] += 1
            else:
                parts.append(_duration(now - unit["started"]))
            self.record("⚠" if gaps else "✓", " · ".join(parts), now)
            self.shown = (self.current, round(100 * self.done))
            return True

    def taken_over(self) -> None:
        """Say once per phase, and in the threat analysis once per method, that its first job came from the earlier run.

        Whether a job matches is known only once its request is built, so the line follows the first such
        job instead of the phase's start; the done lines say how much came from the earlier run.
        """
        with _AssessmentConsole._lock:
            key = (self.phase, self.method)
            if not self.phase or key in self.announced:
                return
            self.announced.add(key)
            self.record("·", f"taken over from {self._source()}")

    def _source(self) -> str:
        """Where taken-over steps come from: a resumed run continues its own earlier attempt."""
        return "the earlier attempt" if self.resumed else "the earlier run"

    def _earlier(self, reused: int, total: int) -> str:
        """`` · from the earlier run`` when all ``total`` steps came from it, how many otherwise; "" for none."""
        if not reused:
            return ""
        return f" · from {self._source()}" if reused >= total else f" · {reused} of {total} from {self._source()}"

    def _mark_step(self, step: str) -> None:
        if self.usage_mark:
            self.step_usage[step] = self.usage_mark()

    def _step_cost(self, step: str) -> str:
        """`` · ≈ USD 1.20 · 0.5M tokens`` for a step that ended, once; "" when it cost nothing or had no mark."""
        before = self.step_usage.pop(step, None)
        cost = usage_text(before, self.usage_mark(), show_costs=self.show_costs) if before and self.usage_mark else ""
        return f" · {cost}" if cost else ""

    def _advance(self, fraction: float) -> None:
        """Record ``fraction`` of the current phase as finished."""
        self.fraction = max(self.fraction, min(fraction, 1.0))
        done = max(self.done, self._share())
        self._count_replay(done - self.done)
        self.done = done

    def _share(self) -> float:
        """The run's finished share at the current phase's ``fraction``."""
        plan = self.plan if self.phase in self.plan else [*self.plan, self.phase]
        before = sum(self._weight(name) for name in plan[: plan.index(self.phase)])
        total = sum(self._weight(name) for name in plan)
        return (before + self._weight(self.phase) * self.fraction) / total

    def _count_replay(self, share: float) -> None:
        """Count ``share`` and the time since the last advance as replayed while the run takes over jobs.

        A stretch in which jobs were taken over and none ran is replayed, one in which a job ran is this
        attempt's work. A stretch without a finished job continues the one before: concurrent subjects
        advance the share at their start, before their jobs finish.
        """
        now, counts = self.clock(), self.job_counts() if self.job_counts else (0, 0)
        reused, ran = (count - before for count, before in zip(counts, self.advanced_jobs, strict=True))
        if reused or ran:
            self.replaying = not ran
        if self.replaying:
            self.replayed_share += share
            self.replayed_seconds += now - self.advanced_at
        self.advanced_jobs, self.advanced_at = counts, now

    def _expected_total(self) -> float:
        """Seconds the planned phases take at their measured minutes, scaled to the component count.

        Used until a component has finished and the run's own speed is known.
        """
        plan = self.plan if self.phase in self.plan else [*self.plan, self.phase]
        return 60 * sum(self._weight(name) for name in plan)

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

    def continue_from(self, seconds: int, *, resumed: bool = True) -> None:
        """Add earlier working time to ELAPSED, in parentheses, and the total cost to the phases' done lines.

        The time is that of a resumed run's earlier attempts or, without ``resumed``, of the unfinished
        run a new run takes over. LEFT still follows this attempt's speed alone: its share starts again
        from the first phase, so time of earlier attempts would inflate it.
        """
        self.worked_before, self.resumed = seconds, resumed

    def _total(self, now: float) -> str:
        """The working time including earlier attempts or the run taken over; empty without either."""
        return _elapsed(self.worked_before + now - self.run_started) if self.worked_before else ""

    def _elapsed_width(self) -> int:
        """ELAPSED's width; a resumed run's adds its total, such as ``1h05m (2h10m)``."""
        return 13 if self.worked_before else 7

    def _run(self, now: float) -> str:
        """The run columns: finished share, elapsed time, and the remaining time at the measured speed."""
        share, elapsed, left = self._run_fields(now)
        if total := self._total(now):
            elapsed = f"{elapsed} ({total})"
        return f"{share:>8}  {elapsed:>{self._elapsed_width()}}  {left:>6}"

    def _run_fields(self, now: float) -> tuple[str, str, str]:
        elapsed, left = now - self.run_started, ""
        if self.done >= 1:
            share = "100%"
        else:
            share = f"~{min(99, round(100 * self.done))}%" if self.components else "planning"
            # Taken-over work would make the work ahead look as fast; below one percent its remainder is rounding.
            worked = self.done - self.replayed_share
            if worked >= 0.01 and self._measured():
                left = "~" + _elapsed((elapsed - self.replayed_seconds) * (1 - self.done) / worked)
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
        # A threat analysis line names its method first; a long detail wraps under the text after it.
        method = self.method if event not in ("start", "done") else ""
        lead = f"{method:<{self._METHOD_WIDTH}}  " if method else ""
        run = self._run(now)
        if live:
            event = SPINNER[self.frame % len(SPINNER)]
            if self.components:
                detail = f"{self.st.bar(round(100 * self.done), 100, self.BAR_WIDTH)}  {detail}".rstrip()
        # Free text comes last, so a long detail never shifts a column.
        row = f"{phase:<{self._PHASE_WIDTH}}  {event:<{self._EVENT_WIDTH}}  {run}  {lead}{detail}"
        if not self.st.enabled:
            if not self.wraps() and "\n" not in detail:
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
        head = f"{phase_cell}  {event_cell}  {run_cell}  {st(lead, 'bold') if lead else ''}"
        # A long detail wraps under its own column instead of at the screen
        # edge; the status line is cut by `_status` instead.
        indent, pieces = self._wrap_detail(len(ANSI_RE.sub("", head)), detail, now, live)
        cells = [st(piece, "warn") if event == "⚠" and piece else piece for piece in pieces]
        if event == "start" or (method and detail.startswith("start")):
            # The models of the phase's or the method's roles carry the colour the header gives its models.
            key = method or self.phase or ""
            for name in dict.fromkeys(model for _, model in self.phase_models.get(key, [])):
                cells = [piece.replace(name, st(name, "agent")) for piece in cells]
        return self._join(head, indent, cells)

    def _wrap_detail(self, head: int, detail: str, now: float, live: bool) -> tuple[int, list[str]]:
        """(indent, pieces) of a detail after a `head` columns wide grid head.

        A long detail continues under its own column. Where --width leaves that
        column too narrow, the detail starts on the next line after the time stamp.
        """
        indent = len(self._stamp(now)) + 2 + head
        fit = self.columns() - 1 - indent
        if "\n" in detail:
            # A list: each line starts under the detail column; a long entry continues two columns further in.
            wrapped = self.st.enabled or self.wraps()
            return indent, [
                piece
                for line in detail.split("\n")
                for piece in (
                    textwrap.wrap(line, fit, subsequent_indent="  ", break_on_hyphens=False)
                    if wrapped and fit >= 20
                    else [line]
                )
            ]
        if live or len(detail) <= fit:
            return indent, [detail]
        if fit >= 20:
            return indent, textwrap.wrap(detail, fit, break_on_hyphens=False)
        if not self.wraps():
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
            if self.checked:
                self._out("")
            self._out(
                self.st(
                    f"{'TIME':<8}  {'PHASE':<{self._PHASE_WIDTH}}  {'EVENT':<{self._EVENT_WIDTH}}  "
                    f"{'PROGRESS':>8}  {'ELAPSED':>{self._elapsed_width()}}  {'LEFT':>6}  DETAIL",
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
        if named := [key for key, value in rows if key in self.METHODS and not value.startswith("skipped")]:
            self.methods = named
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
            elif self.wraps():
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
        fit = self.columns() - 1 - (len(indent) + width + 2) if st.enabled or self.wraps() else 0
        groups = {"": rows}
        if sectioned:
            groups = {"Run": [], "Scope": [], "Workflow & results": [], "Threat analysis methods": []}
            for key, value in rows:
                section = (
                    "Scope"
                    if key in ("Focus", "Abuse cases", "Coverage", "Excludes", "Trust mode")
                    else "Workflow & results"
                    if key in ("Pipeline", "Artifacts")
                    else "Threat analysis methods"
                    if key in self.METHODS
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

    # "Platform settings", the longest start-check label.
    _CHECK_WIDTH = 17

    def preflight(self, checks) -> None:
        """Completed start checks as a Pre-run checks block under the run summary, above the grid.

        Console only: the checks finished before the run, so no progress event follows.
        A later call, such as the platform settings check, continues the same block.
        """
        if not checks:
            return
        st = self.st
        if not self.checked:
            self.checked = True
            self._unstamped(st("  Pre-run checks", "bold"))
        # Like the facts: a long message wraps flush under its own column on a terminal or under --width.
        indent = 4 + 2 + self._CHECK_WIDTH + 2
        fit = self.columns() - 1 - indent if st.enabled or self.wraps() else 0
        for symbol, label, message in checks:
            pieces = textwrap.wrap(message, fit, break_on_hyphens=False) if fit > 20 and len(message) > fit else []
            first, *more = pieces or [message]
            mark = st(symbol, self.EVENT_ROLES.get(symbol) or "muted")
            self._unstamped(f"    {mark} {st(f'{label:<{self._CHECK_WIDTH}}', 'muted')}  {first}")
            for piece in more:
                self._unstamped(" " * indent + piece)

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
            skip = None if self.verbose else self._BUDGET_SKIP.fullmatch(text)
            with _AssessmentConsole._lock:
                if skip:
                    self.budget_skips[skip[1]] += 1
                if not skip or self.budget_skips[skip[1]] == 1:
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
        reused = text.endswith(self.REUSED)
        if reused:
            text = text.removesuffix(self.REUSED)
        # Steps name repository components; only printable text reaches the status line.
        headline = text.partition("\n")[0]
        self.activity = "".join(char if char.isprintable() else "?" for char in headline)[: self._NAME_MAX]
        self.activity_started = time.monotonic()
        prefix, phase = next(((p, name) for p, name in self.PHASES if text.startswith(p)), (None, None))
        if phase is None:
            # Before the first phase a plain line; inside a phase a progress line of it.
            if not self.phase:
                self.write(text)
            elif not (self.phase == "Threat analysis" and self._verify_step(text, self.clock(), reused)):
                self.record("·", text)
            return
        now = self.clock()
        position = self._POSITION.search(text)
        # Components analyzed in parallel report together; only the first starts the phase.
        with _AssessmentConsole._lock:
            if phase != self.phase:
                self.close(now)
                self.phase, self.started, self.finished_jobs = phase, now, 0
                self.current, self.count, self.positioned, self.parts = "", None, False, {}
                self.units, self.units_done = {}, 0
                self.verify_done, self.verify_running, self.steps, self.step_times = 0, {}, {}, {}
                self.verify_components_done = 0
                # The threat analysis opens with the scanners; its start line belongs to the phase.
                self.method, self.method_reused = "", Counter()
                self.corrections, self.budget_skips = Counter(), Counter()
                self.phase_jobs = self.job_counts() if self.job_counts else (0, 0)
                self.phase_usage = self.usage_mark() if self.usage_mark else None
                self.step_usage = {}
                self.fraction = 0.0
                self._advance(0.0)
                scope = _count_noun(int(position[2]), self.NOUNS[prefix]) if position and prefix in self.NOUNS else ""
                self._header()
                self.record(
                    "start",
                    " ".join(
                        part
                        for part in (
                            " · ".join(part for part in (scope, self._description(phase)) if part),
                            self.phase_agents(phase),
                        )
                        if part
                    ),
                    now,
                )
                if phase == "Threat analysis":
                    self.method = "Scanners"
                self.shown = (self.current, round(100 * self.done))
                if self.on_phase:
                    self.on_phase()
        if prefix in self.UNIT_STEPS:
            self._unit_step(prefix, text, position, now, reused)
            return
        if prefix == "Scanners · ":
            # The run header says what the scanners check; their line says what they found and how long it took.
            head, *detail = text[len(prefix) :].split("\n")
            self.record("·", "\n".join([f"{head} · {_duration(now - self.started)}", *detail]), now)
            return
        if prefix in self.STATED:
            self.record("·", text, now)
            return
        if prefix == "Abuse cases to verify":
            # The step lists one "ID  title" per line; names come from case files and model output.
            entries = [
                "".join(char if char.isprintable() else "?" for char in entry)[: self._NAME_MAX]
                for entry in text.split("\n")[1:]
            ]
            self.record("·", "\n".join([f"{_count_noun(len(entries), 'abuse case')} to verify", *entries]), now)
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
    # start, each finished survey job, its evidence review and its end.
    UNIT_STEPS = (
        "Surveying component",
        "Finished survey job",
        "Independently verifying evidence",
        "Analyzed component",
    )
    UNIT_NAME = 26

    def _unit_step(self, prefix: str, text: str, position, now: float, reused: bool = False) -> None:
        """Track one concurrently analyzed component; the share follows finished work, not starts."""
        name = self._POSITION.sub("", text[len(prefix) :].lstrip(": "))
        found = self._FOUND.search(name) if prefix == "Analyzed component" else None
        if found:
            name = name[: found.start()]
        name = "".join(char if char.isprintable() else "?" for char in name)[: self._NAME_MAX]
        with _AssessmentConsole._lock:
            if prefix == "Surveying component":
                self.positioned = True
                if "Survey" not in self.steps:
                    self.steps["Survey"] = now
                    self._mark_step("Survey")
                    self.method = "Survey"
                    count = f" · {_count_noun(int(position[2]), 'component')}" if position else ""
                    self.record(
                        "·", " ".join(part for part in ("start" + count, self.phase_agents("Survey")) if part), now
                    )
                if position:
                    self.count = (max(int(position[2]), self.count[0] if self.count else 0), "component")
                self.units[name] = {"done": 0, "total": None, "stage": "STRIDE", "started": now}
                line = f"component {position[1]}/{position[2]} · {name}" if position else name
                if not self.live:
                    self.record("·", line, now)
            elif prefix == "Finished survey job":
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
                finished = name + (f" · {found[1]}" if found else "")
                # A component taken from the earlier run took no time worth naming; the done line counts it.
                if reused:
                    self.method_reused["Survey"] += 1
                elif unit:
                    finished += f" · {_duration(now - unit['started'])}"
            total = self.count[0] if self.count else 0
            if total:
                running = sum(self._unit_progress(unit) / 100 for unit in self.units.values())
                self._advance(self._survey_share() * (self.units_done + running) / total)
                # Under concurrency no single component is current; the bars name the running ones.
                self.current = f"{self.units_done}/{total} components done"
            if finished is not None:
                # Counts completions, so it names no start slot such as a start line's "component 4/9".
                # Its own event, so `done` marks only a phase's end.
                self.record("✓", f"{self.units_done}/{total or '?'} {finished}", now)
            # A permanent line names the component; the heartbeat need not repeat the count.
            self.shown = (self.current, round(100 * self.done))

    @staticmethod
    def _unit_progress(unit: dict) -> int:
        """Percent of one component: its survey jobs, then one share for the evidence review."""
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
            return "Survey"
        return f"{unit['done']}/{unit['total']} Survey jobs"

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
            produced.extend(f"{step} {_duration(seconds)}" for step, seconds in self.step_times.items())
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
            produced.extend(
                f"{_count_noun(count - 1, f'more {role} job')} skipped for budget"
                for role, count in self.budget_skips.items()
                if count > 1
            )
            if self.job_counts:
                reused, ran = (count - before for count, before in zip(self.job_counts(), self.phase_jobs, strict=True))
                if reused:
                    produced.append(
                        f"partly from {self._source()}" if ran else f"from {self._source()}, no model calls"
                    )
            # A continued run also says what all its results cost, those taken over included.
            mark = self.usage_mark() if self.usage_mark else None
            if (
                self.phase_usage
                and mark
                and (cost := usage_text(self.phase_usage, mark, bool(self.worked_before), show_costs=self.show_costs))
            ):
                produced.append(cost)
            self._advance(1.0)
            if self.phase == self.plan[-1]:
                self.done = 1.0
            self.record("done", " · ".join(produced), now)
        self.phase, self.method = None, ""
