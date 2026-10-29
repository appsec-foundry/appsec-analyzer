"""One bounded, receipted semantic job of the existing assessment controller.

This module has no pipeline, role registry or publication decision. The
controller supplies the role, instructions, contract, scope and successor.
Cached outputs confer no source authority and are revalidated before use.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import stat
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from jsonschema import Draft202012Validator
from shared._atomic_io import atomic_write_json

from appsec_analyzer.execution_limits import DEFAULT_MAX_PARALLEL, DIVISIBLE_MAX_PARALLEL, validate_max_parallel
from runtime.analyst_host import HostCancelled, HostTimeout, TransportError
from runtime.assessment_host import MAX_EXCHANGES, ExchangeError, ExchangeResult, ModelAnswerFailure, run_exchange
from runtime.multi_repo_discovery import MAX_CALL_SECONDS, BudgetedHost, BudgetExhausted, DiscoveryBudget

ROOT = Path(__file__).resolve().parents[2]
RECEIPT_SCHEMA = ROOT / "schemas/assessment-job-receipt.schema.json"
MAX_ARTIFACT_BYTES = 2_097_152
# 1,600 component analyses/verifications, 4,096 connection reviews, and
# bounded architecture/boundary/report jobs, each with at most six exchanges.
MAX_ASSESSMENT_CALLS = (1600 * 2 + 4096 + 500 + 16 * 4 + 16) * MAX_EXCHANGES
MAX_ASSESSMENT_SECONDS = 43_200
# Local composition, validation and publication need time even after the last call.
FINALIZATION_SECONDS = 120
# A pending job reserves the average accepted job of its role plus half again,
# which leaves room for corrections without multiplying one outlier across
# every pending batch.
COST_HEADROOM = 1.5
REPORT_JOB = "stage2:security-architecture"
SUMMARY_JOB = "stage2:management-summary"


def digest(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


@dataclass
class AssessmentBudget(DiscoveryBudget):
    """Aggregate the full assessment rather than the discovery phase alone."""

    max_parallel: int = field(default=DEFAULT_MAX_PARALLEL, kw_only=True)
    # Whether max_parallel is the analyzer's default rather than a value the user chose.
    parallel_is_default: bool = field(default=False, kw_only=True)
    # The run's component count, known after the architecture.
    components: int | None = field(default=None, kw_only=True)
    subscription_label: str = field(default="ChatGPT subscription", kw_only=True)
    # Whether the USD amounts value Claude subscription usage at API prices; display wording only.
    api_prices: bool = field(default=False, kw_only=True)
    # The worst case of one call on an API host, which sends no call whose ceiling is below it; 0 for CLI hosts.
    call_floor_usd: float = field(default=0.0, kw_only=True)

    def max_inflight(self) -> int:
        return self.workers

    @property
    def workers(self) -> int:
        """The parallel jobs a pool runs: the default of four becomes three where three components divide evenly."""
        if (
            self.parallel_is_default
            and self.max_parallel == DEFAULT_MAX_PARALLEL
            and self.components
            and self.components % DIVISIBLE_MAX_PARALLEL == 0
        ):
            return DIVISIBLE_MAX_PARALLEL
        return self.max_parallel

    def __post_init__(self):
        try:
            validate_max_parallel(self.max_parallel)
        except ValueError as exc:
            raise ExchangeError(str(exc)) from None
        if (
            type(self.subscription) is not bool
            or type(self.subscription_label) is not str
            or not self.subscription_label
            or (
                self.subscription
                and (self.max_usd is not None or self.call_usd is not None or self.spent_usd is not None)
            )
            or (
                not self.subscription
                and (
                    any(
                        type(v) not in (int, float) or not math.isfinite(v) or v <= 0
                        for v in (self.max_usd, self.call_usd)
                    )
                    or self.call_usd > self.max_usd
                    or self.spent_usd != 0
                )
            )
            or type(self.max_calls) is not int
            or not 1 <= self.max_calls <= MAX_ASSESSMENT_CALLS
            or type(self.timeout_s) is not int
            or not 1 <= self.timeout_s <= MAX_ASSESSMENT_SECONDS
            or self.calls != 0
        ):
            raise ExchangeError("Invalid full-assessment budget")
        self.deadline = time.monotonic() + self.timeout_s
        self._clocks = (time.monotonic(), time.time())
        self.failed = False
        # What jobs reused from an earlier run charged to this one; the closing line names it.
        self.reused_calls, self.reused_usd = 0, 0.0
        self.init_retries()
        self.required = {}
        self.observed = {}
        self.reserve_completion = False
        self.on_budget_increase = None
        # Controller-set shares of optional work, {group: (usd, calls)}. They
        # live in memory only; the controller recomputes them on resume.
        self.holds = {}

    def request_more_budget(self, should_stop) -> bool:
        if self.subscription or self.on_budget_increase is None or self.unsettled or self._inflight or should_stop():
            return False
        group, _role, optional = getattr(self._local, "job", (None, None, False))
        # While source analysis is pending, its reserve shrinks with every
        # accepted batch, and the controller retries the optional job's budget
        # gap afterwards; asking now would pause the run for nothing.
        if optional and any(key not in (group, REPORT_JOB) for key in self.required):
            return False
        # A hold divides the money that is left; it never asks for more.
        if optional and self.holds:
            return False
        previous = self.max_usd
        self.on_budget_increase(should_stop)
        return self.max_usd > previous

    def hold(self, group, usd, calls):
        """Keep `usd` and `calls` for `group`'s optional jobs until `release(group)`.

        Only optional jobs of other groups see less; required work outranks a
        hold, and the completion reserve still applies to every job. A
        subscription run holds calls only (`usd` is None). A hold may exceed
        what is left: other optional jobs then become budget gaps, and the held
        group spends only what is actually available.
        """
        if (
            type(group) is not str
            or not group
            or type(calls) is not int
            or calls < 0
            or (
                usd is not None
                if self.subscription
                else type(usd) not in (int, float) or not math.isfinite(usd) or usd < 0
            )
        ):
            raise ExchangeError("Invalid budget hold")
        with self._lock:
            self.holds[group] = (0.0 if self.subscription else float(usd), calls)

    def release(self, group):
        with self._lock:
            self.holds.pop(group, None)

    def _held_for_others(self, index):
        """What other groups hold against the current optional job: 0 usd, 1 calls."""
        group, _role, optional = getattr(self._local, "job", (None, None, False))
        if not optional:
            return 0
        return sum(held[index] for key, held in self.holds.items() if key != group)

    def plan_completion(self):
        """Protect the required renderer; only the controller may change this plan."""
        self.reserve_completion = True
        self.plan_required(REPORT_JOB, "secarch_renderer", 1)

    def plan_required(self, group, role, count):
        with self._lock:
            if count:
                self.required[group] = (role, count)
            else:
                self.required.pop(group, None)

    @contextmanager
    def job(self, group, role, optional):
        self._local.job = (group, role, optional)
        try:
            yield
        finally:
            del self._local.job

    def accepted(self, group, role, usd, seconds=None):
        """Learn only from accepted jobs under this run's fixed model selection."""
        with self._lock:
            cost, jobs, duration = self.observed.get(role, (0.0, 0, 0.0))
            # Subscription completion reserves use calls and time only.
            estimate = 0.0 if self.subscription else usd
            self.observed[role] = (cost + estimate, jobs + 1, max(duration, seconds or 0.0))
            if group in self.required:
                planned_role, count = self.required[group]
                self.plan_required(group, planned_role, count - 1)

    def usage_mark(self) -> dict:
        """Calls run and money spent so far by this session, and how much of it the hosts itemised.

        Jobs reused from an earlier run are not part of it, except in ``total_usd``, what the run has
        cost so far. The console takes the difference of two marks to say what a step cost.
        """
        with self._lock:
            return {
                "calls": self.calls - self.reused_calls,
                "usd": None if self.subscription else self.spent_usd - self.reused_usd,
                "total_usd": None if self.subscription else self.spent_usd,
                "itemised": sum(row["calls"] for row in self.ledger.values()),
                "tokens": sum(self.tokens(row) for row in self.ledger.values()),
            }

    def job_usd(self, role, fallback_role):
        """The reserved cost of one more job of ``role``, measured on ``fallback_role`` while ``role`` has none."""
        if not self.observed.get(role, (0.0, 0, 0.0))[1]:
            role = fallback_role
        return self._estimate(role)[0]

    def _estimate(self, role):
        cost, jobs, seconds = self.observed.get(role, (0.0, 0, 0.0))
        # A cold role keeps a full call allowance. Measurements include all
        # exchanges of a job, so earlier corrections are part of the average.
        allowance = 0.0 if self.subscription else (max(0.05, COST_HEADROOM * cost / jobs) if cost else self.call_usd)
        return allowance, 2 * seconds if seconds else MAX_CALL_SECONDS

    def _optional_usd(self, role):
        """What an optional job of ``role`` must find above the reserves before it starts."""
        if self.observed.get(role, (0.0, 0, 0.0))[0]:
            return self._estimate(role)[0]
        # A cold optional role is expected to cost what this run's accepted
        # jobs cost on average, so the money above the reserves is not held
        # back for a full call allowance. Reserves keep the full allowance.
        cost = sum(usd for usd, _jobs, _seconds in self.observed.values())
        jobs = sum(count for _usd, count, _seconds in self.observed.values())
        return min(self.call_usd, max(0.05, COST_HEADROOM * cost / jobs)) if cost else self.call_usd

    def _reserve(self):
        group, _role, optional = getattr(self._local, "job", (None, None, False))
        dollars, serial, parallel = 0.0, 0.0, 0.0
        parallel_count = 0
        for key, (role, count) in self.required.items():
            # Required source analysis protects the report; optional work also
            # protects every remaining STRIDE batch. Running calls are already
            # charged, so this deliberately errs on the conservative side.
            if key == group or (not optional and key != REPORT_JOB):
                continue
            usd, seconds = self._estimate(role)
            dollars += count * usd
            if role == "stride_analyzer":
                parallel_count += count
                parallel = max(parallel, seconds)
            else:
                serial += count * seconds
        if dollars:
            # An API host admits the last reserved call only with its worst case left.
            dollars += self.call_floor_usd
        # The last, partially filled worker group still needs a full job slot.
        parallel_seconds = math.ceil(parallel_count / self.workers) * parallel
        return dollars, math.ceil(serial + parallel_seconds) + FINALIZATION_SECONDS

    def available_usd(self):
        if self.subscription:
            return 0.0
        available = super().available_usd() - self._held_for_others(0)
        if not self.reserve_completion:
            return available
        reserved, _ = self._reserve()
        available -= reserved
        group, role, optional = getattr(self._local, "job", (None, None, False))
        # Once the required report is accepted, its unused reserve can fund
        # the summary even below a full estimated job. Admission still caps
        # every exchange at the actual remainder and enforces time/call limits.
        finishing_summary = group == SUMMARY_JOB and role == "ms_renderer" and REPORT_JOB not in self.required
        if optional and not finishing_summary and available + 1e-9 < self._optional_usd(role):
            return 0.0
        return available

    def _charge_sleep(self):
        """Take the time the machine slept off the deadline.

        The monotonic clock stops during suspend, but the run's limit
        (`expires_at`) is wall time: a run must not wake up and keep going
        after it expired.
        """
        with self._lock:
            monotonic, wall = time.monotonic(), time.time()
            slept = (wall - self._clocks[1]) - (monotonic - self._clocks[0])
            if slept > 0:
                self.deadline -= slept
            self._clocks = (monotonic, wall)

    def call_seconds(self):
        seconds = self.remaining_seconds()
        if self.reserve_completion:
            _, reserved = self._reserve()
            seconds = math.floor(self.deadline - time.monotonic() - reserved)
            if seconds < 1:
                raise BudgetExhausted("Assessment time budget reserved for required completion work")
        return seconds

    def call_limit(self):
        limit = self.max_calls - self._held_for_others(1)
        if not self.reserve_completion:
            return limit
        group, _role, optional = getattr(self._local, "job", (None, None, False))
        reserved = sum(
            2 * count for key, (_, count) in self.required.items() if key != group and (optional or key == REPORT_JOB)
        )
        return limit - reserved

    def remaining_seconds(self):
        # Every individual exchange still has the existing one-hour ceiling.
        self._charge_sleep()
        try:
            return min(3600, super().remaining_seconds())
        except HostCancelled as exc:
            raise BudgetExhausted("Assessment aggregate time budget exhausted") from exc


def _read_json(path: Path):
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_ARTIFACT_BYTES:
            raise ExchangeError("Assessment artifact is not a bounded regular file")
        return json.loads(path.read_text(encoding="utf-8"))
    except ExchangeError:
        raise
    except (OSError, ValueError):
        raise ExchangeError("Assessment artifact is unreadable or malformed") from None


def _ranges(slices) -> list[dict]:
    return [{k: row[k] for k in ("repository_id", "path", "sha256", "start_line", "end_line")} for row in slices]


def _job_id(role, selector) -> str:
    return "job-" + digest({"role": role, "selector": selector})[:24]


class AssessmentJobs:
    def __init__(
        self,
        scope,
        directory,
        budget,
        host_factory,
        should_stop,
        checkpoint,
        *,
        cache=None,
        prompt_capacity=None,
        diagnostics=None,
        redo_stale=False,
    ):
        """`cache` holds an earlier, unfinished run's accepted jobs (see assessment_state.CACHE_NAME).

        A cached job is adopted only when it still matches its request and
        passes today's acceptance checks: its calls and cost are charged to
        this run before it moves into `directory`, so every receipt there is
        covered by the run's accounting. A cached job that no longer fits is
        discarded and redone. A receipt in `directory` stays strict, unless
        `redo_stale` says the run resumed after a plugin change (REQ-016): a
        receipt that no longer fits is then redone as well, and the cost it
        recorded stays in the run's accounting. A changed artifact still stops.
        """
        self.scope = scope
        self.directory = Path(directory)
        self.redo_stale = redo_stale
        self.budget = budget
        self.host_factory = host_factory
        self.prompt_capacity = prompt_capacity
        self.diagnostics = diagnostics
        self.should_stop = should_stop
        # MR-16: concurrent jobs share receipts, timing and the checkpoint file.
        self._lock = threading.RLock()

        def locked_checkpoint():
            with self._lock:
                checkpoint()

        self.checkpoint = locked_checkpoint
        self.scope_sha256 = scope.inventory()["scope_sha256"]
        if self.directory.exists() and not stat.S_ISDIR(self.directory.lstat().st_mode):
            raise ExchangeError("Assessment job directory must be a real directory")
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)
        self.cache = None
        if cache is not None and Path(cache).exists():
            if not stat.S_ISDIR(Path(cache).lstat().st_mode):
                raise ExchangeError("Assessment job cache must be a real directory")
            self.cache = Path(cache)
        # Wall time and calls per role of the jobs this session ran; a reused
        # job counts as reused, since its time was spent in an earlier run.
        self.timing: dict[str, dict] = {}
        # Jobs this object reused and ran; a view counts only its own, so the
        # console can mark a component whose every job was reused.
        self.reused, self.ran = 0, 0
        # Only accepted in-memory results enter a budget interruption report.
        # Shared by component views; no receipt is trusted merely by reading it.
        self.accepted_results: dict[str, dict] = {}
        # Optional jobs replaced after a model failure, in run order (OR-39).
        self.gaps: list[dict] = []
        # Controller-owned progress callback, shared by forked component jobs.
        self.on_gap = None
        # Called after each job taken over from an earlier run's accepted result, also from forked jobs.
        self.on_reused = None
        # Run warnings the controller derives from accepted jobs, in run order.
        self.notes: list[str] = []
        # Coverage statements that need no action, such as files no target covered:
        # {component, files, text}; the console collapses them unless --verbose,
        # and the model records them as meta.unexamined_source.
        self.infos: list[dict] = []
        # Set by a concurrent caller after a failure: no further job starts (MR-16).
        self.halt = None

    def context_limit(self, instructions, schema):
        from runtime.assessment_host import context_capacity

        return context_capacity(instructions, schema, self.prompt_capacity)

    def view(self):
        """Jobs for one concurrently analyzed component, with its own notes and gaps (MR-16).

        Receipts, accounting and timing stay shared; `join` appends the view's
        notes and gaps, so the caller keeps component order whatever finishes first.
        """
        child = copy.copy(self)
        child.notes, child.gaps, child.infos = [], [], []
        child.reused, child.ran = 0, 0
        return child

    def join(self, child) -> None:
        self.notes.extend(child.notes)
        self.gaps.extend(child.gaps)
        self.infos.extend(child.infos)

    def _record(self, role: str, *, seconds: float | None = None, calls: int = 0) -> None:
        with self._lock:
            row = self.timing.setdefault(role, {"jobs": 0, "reused": 0, "calls": 0, "seconds": 0.0})
            if seconds is None:
                row["reused"] += 1
                self.reused += 1
            else:
                row["jobs"] += 1
                row["calls"] += calls
                row["seconds"] += seconds
                self.ran += 1

    def job_counts(self) -> tuple[int, int]:
        """Jobs reused and jobs run so far in this session, across all views."""
        with self._lock:
            return sum(row["reused"] for row in self.timing.values()), sum(row["jobs"] for row in self.timing.values())

    def has_accepted(self, role, selector) -> bool:
        """Whether an accepted receipt of this job waits for reuse, in this run or in the cache.

        For estimates only: whether the receipt still matches is decided when the
        job runs, so a job whose request changed runs again despite it.
        """
        name = _job_id(role, selector) + ".receipt.json"
        for folder in (self.directory, self.cache):
            if folder is None or not (folder / name).is_file():
                continue
            try:
                receipt = _read_json(folder / name)
            except ExchangeError:
                return False
            return isinstance(receipt, dict) and receipt.get("scope_sha256") == self.scope_sha256
        return False

    def execute(self, **kwargs):
        """Return the accepted artifact of one controller-selected job."""
        return self.exchange(**kwargs).artifact

    def _gap(self, gap):
        self.gaps.append(gap)
        if self.on_gap is not None:
            self.on_gap(dict(gap))

    def _remember(self, role, selector, artifact):
        findings = []
        threats = artifact.get("threats", []) if role == "stride_analyzer" else []
        for threat in threats[:200]:
            evidence = threat.get("evidence") or {}
            findings.append(
                {
                    "title": str(threat.get("title", ""))[:300],
                    "repository_id": evidence.get("repository_id", ""),
                    "file": evidence.get("file", ""),
                    "line": evidence.get("line", 1),
                }
            )
        with self._lock:
            self.accepted_results[selector] = {
                "role": role,
                "selector": selector,
                "finding_count": len(threats),
                "findings": findings,
            }

    def exchange(self, **kwargs):
        from runtime.assessment_diagnostics import failure_fields, safe_reason, transport_summary

        trace = self.diagnostics.job(kwargs["role"], kwargs["selector"]) if self.diagnostics else None
        if trace:
            trace.emit("job_start")
        try:
            return self._exchange(**kwargs, trace=trace)
        except BaseException as error:
            if isinstance(error, ModelAnswerFailure):
                context = kwargs.get("context") or {}
                component = context.get("component") or {}
                error.assessment_job = {
                    "role": kwargs["role"],
                    "selector": kwargs["selector"],
                    "label": safe_reason(str(component.get("name") or context.get("label") or "")),
                    "subject": "Component" if component.get("name") else "Repository",
                    "reason": safe_reason(str(error)),
                }
                if trace:
                    error.diagnostic_path = self.diagnostics.path
            if trace:
                trace.emit("job_failed", **failure_fields(error))
                if isinstance(error, (ExchangeError, TransportError, HostCancelled)):
                    # Keep exception type, accounting and retry metadata intact.
                    detail = transport_summary(error) if isinstance(error, TransportError) else safe_reason(str(error))
                    error.args = (
                        f"{trace.fields['job_id']} {trace.fields['role']} {trace.fields['selector']}: {detail}",
                    )
            raise

    def _exchange(
        self,
        *,
        role,
        selector,
        instructions,
        context,
        schema,
        allowed_sources,
        validate,
        normalize=None,
        on_failure=None,
        preload=(),
        budget_group=None,
        trace=None,
        salvage=None,
        shared_context_keys=0,
    ):
        """Execute or resume one job, including its accepted retrieval receipt.

        ``normalize`` derives controller-known fields of each complete result
        before review (see ``run_exchange``); the receipt records the
        normalized artifact. Its identity joins the request, so a changed
        normalizer redoes the job instead of failing a resumed one.

        ``preload`` slices reach the first packet (see ``run_exchange``) and
        join the request identity, as does ``salvage``, which may keep part
        of a result still rejected after the last correction.
        ``shared_context_keys`` only places the prompt's cache blocks (see
        ``run_exchange``); the text stays the same, so it stays out of the identity.

        ``on_failure(reason)`` makes the job optional (decision OR-39): when
        the model returns no acceptable result, a call times out after its
        retries, or the host fails with its cost settled, the job returns that
        deterministic replacement instead of stopping the run, records the gap
        in ``gaps`` and writes no receipt, so a later run retries it. A scope or
        receipt breach, a cancellation and unsettled accounting still stop the
        run. A planned budget stop uses the same explicit replacement before
        another optional call can spend the completion reserve.
        """
        if self.should_stop() or (self.halt is not None and self.halt.is_set()):
            # A stop request is an interruption the run can resume, not a failure.
            raise HostCancelled("Assessment cancelled")
        group = budget_group or selector
        self.budget.remaining_seconds()
        request = {
            "role": role,
            "selector": selector,
            "scope_sha256": self.scope_sha256,
            "instructions_sha256": hashlib.sha256(instructions.encode()).hexdigest(),
            "schema_sha256": digest(schema),
            "context": context,
            "allowed_sources": sorted(allowed_sources),
        }
        if normalize is not None:
            request["normalizer"] = getattr(normalize, "version", None) or normalize.__qualname__
        if salvage is not None:
            request["salvage"] = getattr(salvage, "version", None) or salvage.__qualname__
        if preload:
            request["preload"] = [list(key) for key in preload]
        request_sha256 = digest(request)
        if trace:
            trace.emit("job_request", request_sha256=request_sha256)
        job_id = _job_id(role, selector)
        artifact_path = self.directory / f"{job_id}.json"
        receipt_path = self.directory / f"{job_id}.receipt.json"
        validator = Draft202012Validator(json.loads(RECEIPT_SCHEMA.read_text(encoding="utf-8")))

        def accept(artifact, ranges):
            error = next(iter(Draft202012Validator(schema).iter_errors(artifact)), None)
            if error is not None:
                # The path names the contract's own keys and indices, never a value.
                where = "/".join(str(part) for part in error.absolute_path) or "the root"
                raise ExchangeError(f"Assessment job artifact violates its output contract at {where}")
            for row in ranges:
                if (row["repository_id"], row["path"]) not in allowed_sources:
                    raise ExchangeError("Assessment receipt contains an unauthorized source")
                captured = self.scope.read(row["repository_id"], row["path"], row["start_line"], row["end_line"])
                if captured["sha256"] != row["sha256"]:
                    raise ExchangeError("Assessment receipt refers to changed source")
            validate(artifact, ranges)

        found_path, found_artifact, inherited = receipt_path, artifact_path, False
        if not (receipt_path.exists() or receipt_path.is_symlink()) and self.cache is not None:
            found_path, found_artifact, inherited = (
                self.cache / receipt_path.name,
                self.cache / artifact_path.name,
                True,
            )
        if found_path.exists() or found_path.is_symlink():
            receipt = _read_json(found_path)
            current = (
                validator.is_valid(receipt)
                and receipt["schema_version"] == (2 if self.budget.subscription else 1)
                and receipt["job_id"] == job_id
                and receipt["role"] == role
                and receipt["request_sha256"] == request_sha256
                and receipt["scope_sha256"] == self.scope_sha256
            )
            # A stale cached job is redone; a stale receipt of this run only after a plugin change.
            redo = inherited or self.redo_stale
            if not current and not redo:
                raise ExchangeError("Assessment job receipt is stale or belongs to another request")
            if current and inherited and not found_artifact.is_file():
                current = False
            if current:
                artifact = _read_json(found_artifact)
                # A changed artifact is tampering, not a changed request: never redo it silently.
                if digest(artifact) != receipt["artifact_sha256"]:
                    raise ExchangeError("Assessment job artifact changed after acceptance")
                try:
                    accept(artifact, receipt["source_ranges"])
                except ValueError:
                    if not redo:
                        raise
                    current = False
            if current:
                if inherited:
                    # Charge before the receipt joins this run's jobs, so its accounting
                    # covers every receipt there; the receipt moves last.
                    with self.budget._lock:
                        if self.budget.subscription and self.budget.calls + receipt["calls"] > self.budget.max_calls:
                            raise BudgetExhausted("Cached job calls exceed the selected subscription call limit")
                        self.budget.calls += receipt["calls"]
                        self.budget.reused_calls += receipt["calls"]
                        if not self.budget.subscription:
                            self.budget.spent_usd += receipt["usd"]
                            self.budget.reused_usd += receipt["usd"]
                    self.checkpoint()
                    os.replace(found_artifact, artifact_path)
                    os.replace(found_path, receipt_path)
                slices = tuple(
                    self.scope.read(r["repository_id"], r["path"], r["start_line"], r["end_line"])
                    for r in receipt["source_ranges"]
                )
                self._record(role)
                self.budget.accepted(group, role, receipt["usd"])
                self._remember(role, selector, artifact)
                if trace:
                    trace.emit("job_reused")
                if self.on_reused is not None:
                    self.on_reused()
                return ExchangeResult(copy.deepcopy(artifact), slices, receipt["calls"], receipt["usd"])
            found_path.unlink()
            found_artifact.unlink(missing_ok=True)

        # Persist the call reservation before the host starts. The caller's
        # checkpoint retains failed/unknown accounting and owns resume policy.
        def factory(ceiling):
            self.checkpoint()
            transport = self.host_factory(role, ceiling)
            return trace.wrap(transport) if trace else transport

        def review(artifact, slices):
            accept(copy.deepcopy(artifact), _ranges(slices))

        started = time.monotonic()
        try:
            with self.budget.job(group, role, on_failure is not None):
                result = run_exchange(
                    BudgetedHost(factory, self.budget),
                    self.scope,
                    instructions=instructions,
                    context=context,
                    artifact_schema=schema,
                    allowed_sources=allowed_sources,
                    timeout_s=self.budget.remaining_seconds(),
                    should_stop=self.should_stop,
                    review=review,
                    normalize=normalize,
                    preload=preload,
                    context_limit_bytes=self.context_limit(instructions, schema),
                    salvage=salvage,
                    shared_context_keys=shared_context_keys,
                )
        except BudgetExhausted as exc:
            if on_failure is None or self.budget.unsettled or self.should_stop():
                raise
            reason = "budget reserved for required completion work"
            self._gap({"role": role, "selector": selector, "reason": reason, "budget": True})
            self._record(role, seconds=time.monotonic() - started)
            if trace:
                trace.emit("job_replaced", reason="budget_reserved")
            return ExchangeResult(on_failure(str(exc)), (), 0, None)
        except (ModelAnswerFailure, HostTimeout, TransportError) as exc:
            # Account failures and exhausted shared cooldowns must stop optional jobs too.
            operator = isinstance(exc, TransportError) and exc.reason in (
                "authentication_failed",
                "billing_error",
                "quota_exhausted",
                "rate_limit",
            )
            replaceable = not operator and (
                isinstance(exc, (ModelAnswerFailure, HostTimeout)) or not self.budget.unsettled
            )
            if on_failure is None or not replaceable or self.should_stop():
                if isinstance(exc, HostTimeout):
                    # Name the job, so a hang that survived its retry can be traced.
                    raise HostTimeout(f"{selector}: {exc}") from None
                raise
            reason = re.sub(r"\s+", " ", str(exc))[:300]
            self._gap({"role": role, "selector": selector, "reason": reason})
            self._record(role, seconds=time.monotonic() - started)
            if trace:
                from runtime.assessment_diagnostics import failure_fields

                trace.emit("job_replaced", **failure_fields(exc))
            return ExchangeResult(on_failure(reason), (), 0, None)
        ranges = _ranges(result.source_slices)
        artifact = copy.deepcopy(result.artifact)
        accept(artifact, ranges)
        receipt = {
            "schema_version": 2 if self.budget.subscription else 1,
            "job_id": job_id,
            "role": role,
            "scope_sha256": self.scope_sha256,
            "request_sha256": request_sha256,
            "artifact_sha256": digest(artifact),
            "source_ranges": ranges,
            "calls": result.calls,
            "usd": result.usd,
        }
        validator.validate(receipt)
        atomic_write_json(artifact_path, artifact)
        artifact_path.chmod(0o600)
        atomic_write_json(receipt_path, receipt)
        receipt_path.chmod(0o600)
        self.checkpoint()
        self._record(role, seconds=time.monotonic() - started, calls=result.calls)
        self.budget.accepted(group, role, result.usd, time.monotonic() - started)
        self._remember(role, selector, artifact)
        if trace:
            trace.emit("job_accepted", calls=result.calls)
        return ExchangeResult(artifact, result.source_slices, result.calls, result.usd)
