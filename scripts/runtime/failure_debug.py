"""The private debug file of a run's failed analysis jobs (REQ-050).

When an analysis job fails, whether the run stops or replaces the job and
finishes with missing checks, this file keeps what a person or a model needs to
tell an Analyzer defect from a model error: the exact requests, every model
answer, each rejection with the Analyzer check behind it and that check's code,
and the run's identity.

Unlike the shared diagnostic feed beside it (``events.jsonl``), this file holds
prompts, source excerpts and model answers. It therefore lives in the run's
private diagnostics directory, masks secrets, and Analyzer never sends it
anywhere. Requests and answers are never shortened: past the size bound, a
job's calls move complete into a file of their own next to it.
"""

from __future__ import annotations

import ast
import hashlib
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

FILE_NAME = "failed-jobs.json"
SCHEMA_VERSION = 1
# Past this size a job's calls move, complete, into a file of their own.
MAX_FILE_BYTES = 16 * 1024 * 1024
# A check longer than this shows the lines around its raise site.
MAX_CODE_LINES = 400
# Exception and host text, which is neither a request nor an answer.
MAX_MESSAGE_CHARS = 16_384
_LOCATION = re.compile(r"(?P<function>[\w.<>]+) \((?P<path>[\w./-]+\.py):(?P<line>\d+)\)")

READING_GUIDE = (
    "Each entry in jobs is one failed analysis job. Its calls list every model call in order: the system "
    "instructions (by instructions_sha256 in instructions), the output schema (by schema_sha256 in schemas), the "
    "exact prompt, the model's answer, and the rejection Analyzer returned for it. The trail names the Analyzer "
    "check behind each rejection and the correction that followed; code holds that check's source. A call with "
    "a failure stopped without an answer. Decide for each job whether the cause lies in Analyzer (instructions, "
    "schema or check), in the model's answer, or in the host or environment, and cite the call and the check."
)


def worth_recording(error: BaseException) -> bool:
    """Whether a job's error is a failure to explain; a stop request or a spent budget is none."""
    from runtime.analyst_host import HostCancelled, HostTimeout
    from runtime.multi_repo_discovery import BudgetExhausted

    if isinstance(error, (KeyboardInterrupt, SystemExit, GeneratorExit, BudgetExhausted)):
        return False
    return not isinstance(error, HostCancelled) or isinstance(error, HostTimeout)


def message(text) -> str:
    """Exception or host text without control characters, bounded; secrets are masked when the file is written."""
    text = "".join(c if c.isprintable() or c in "\n\t" else " " for c in str(text))
    if len(text) > MAX_MESSAGE_CHARS:
        half = MAX_MESSAGE_CHARS // 2
        text = text[:half] + " … [message truncated] … " + text[-half:]
    return text


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode(errors="backslashreplace")).hexdigest()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class CallLog:
    """Every model call of one job, kept in memory until the job is accepted or fails."""

    def __init__(self):
        self.calls: list[dict] = []
        self.instructions: dict[str, str] = {}
        self.schemas: dict[str, str] = {}
        self.request_sha256: str | None = None

    def start(self, call_id: str, host_fields: dict, system, prompt, schema) -> dict:
        system = str(system)
        try:
            schema_text = json.dumps(schema, sort_keys=True, allow_nan=False)
        except (TypeError, ValueError):
            schema_text = json.dumps(None)
        system_sha256, schema_sha256 = _sha256(system), _sha256(schema_text)
        self.instructions.setdefault(system_sha256, system)
        self.schemas.setdefault(schema_sha256, schema_text)
        entry = {
            "call_id": call_id,
            **host_fields,
            "started": _now(),
            "instructions_sha256": system_sha256,
            "schema_sha256": schema_sha256,
            "prompt": str(prompt),
        }
        self.calls.append(entry)
        return entry

    @staticmethod
    def answered(entry: dict, reply, seconds: float) -> None:
        entry["seconds"] = round(seconds, 3)
        try:
            # Encoded now: the exchange may still change the answer's objects.
            entry["answer"] = json.dumps(reply.payload, allow_nan=False)
        except (TypeError, ValueError):
            entry["answer"] = json.dumps({"unreadable_answer": message(repr(reply.payload))})
        entry["usd"] = reply.usd if type(reply.usd) in (int, float) else None

    @staticmethod
    def failed(entry: dict, error: BaseException, seconds: float) -> None:
        from runtime.assessment_diagnostics import failure_fields

        entry["seconds"] = round(seconds, 3)
        entry["failure"] = {
            "type": type(error).__name__,
            "code": failure_fields(error).get("reason"),
            "message": message(error),
        }
        usd = getattr(error, "usd", None)
        if type(usd) in (int, float):
            entry["usd"] = usd


def _check_code(location: str, root: Path) -> dict | None:
    """The source of the Analyzer function at `location`, as `code_location` names it."""
    match = _LOCATION.fullmatch(location or "")
    if not match:
        return None
    path = (root / match["path"]).resolve()
    if not path.is_relative_to(root) or path.suffix != ".py" or not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
        tree = ast.parse(text)
    except (OSError, UnicodeDecodeError, SyntaxError, ValueError):
        return None
    line = int(match["line"])
    lines = text.splitlines()
    enclosing = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or 0):
            if enclosing is None or node.lineno >= enclosing.lineno:
                enclosing = node
    start, end = (enclosing.lineno, enclosing.end_lineno) if enclosing else (line, line)
    if enclosing is not None and enclosing.decorator_list:
        start = min(decorator.lineno for decorator in enclosing.decorator_list)
    if end - start + 1 > MAX_CODE_LINES:
        start = max(start, line - MAX_CODE_LINES // 2)
        end = min(end, start + MAX_CODE_LINES - 1)
    return {
        "function": match["function"],
        "path": match["path"],
        "line": line,
        "start_line": start,
        "end_line": end,
        "code": "\n".join(lines[start - 1 : end]),
    }


def _masked(value, changed: list[int]):
    if isinstance(value, str):
        text, applied = mask_text(value)
        if applied:
            changed[0] += 1
        return text
    if isinstance(value, dict):
        return {_masked(str(key), changed): _masked(item, changed) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_masked(item, changed) for item in value]
    return value


class FailureDebug:
    """Writes the run's failed jobs into one private file; a storage failure never changes the run."""

    def __init__(self, directory: Path, run: dict):
        self.directory = Path(directory)
        self.path = self.directory / FILE_NAME
        self.run = run
        self.lock = threading.Lock()
        self.jobs: list[dict] = []
        self.instructions: dict[str, str] = {}
        self.schemas: dict[str, str] = {}
        self.code: dict[str, dict] = {}
        self.written = False
        self.disabled = False
        import appsec_analyzer

        self.root = Path(appsec_analyzer.__file__).resolve().parent.parent

    def record(self, calls: CallLog | None, error: BaseException, *, outcome: str, role, selector, context) -> None:
        """Add one failed job and rewrite the file; `outcome` says whether the run stopped or went on without it."""
        if self.disabled:
            return
        try:
            job = self._job(calls, error, outcome, str(role), str(selector), context)
        except Exception as exc:  # noqa: BLE001 - a defect here must not replace the job's own error
            print(f"⚠ debug file: a failed job could not be recorded ({type(exc).__name__})", file=sys.stderr)
            return
        with self.lock:
            if self.disabled:
                return
            self.jobs.append(job)
            if calls is not None:
                for key, value in calls.instructions.items():
                    self.instructions.setdefault(key, value)
                for key, value in calls.schemas.items():
                    self.schemas.setdefault(key, value)
            try:
                self._write()
                self.written = True
            except (OSError, TypeError, ValueError):
                self.disabled = True
                print("⚠ debug file unavailable: the private file could not be written", file=sys.stderr)

    def _job(self, calls, error, outcome, role, selector, context) -> dict:
        from appsec_analyzer.terminal import code_location
        from runtime.assessment_diagnostics import failure_fields

        context = context if isinstance(context, dict) else {}
        component = context.get("component") if isinstance(context.get("component"), dict) else {}
        label = component.get("name") or context.get("label") or ""
        batch = re.search(r":(\d+)/(\d+)$", selector)
        trail = [dict(entry) for entry in getattr(error, "trail", ()) if isinstance(entry, dict)]
        rows = []
        for entry in calls.calls if calls is not None else ():
            row = dict(entry)
            if "answer" in row:
                row["answer"] = json.loads(row["answer"])
            rows.append(row)
        rejection = getattr(error, "rejection", None)
        if rejection is not None and rows and "answer" in rows[-1] and "rejection" not in rows[-1]:
            # The last answer failed with no correction left, so no correction turn carried its reason.
            rows[-1]["rejection"] = message(rejection)
        location = code_location(error) or None
        for where in [entry.get("check") for entry in trail] + [location]:
            if isinstance(where, str) and where not in self.code:
                found = _check_code(where, self.root)
                if found is not None:
                    self.code[where] = found
        failure = {
            "type": type(error).__name__,
            "code": failure_fields(error).get("reason"),
            "message": message(error),
            "location": location,
        }
        for key in ("exchanges", "source_read_rounds", "rejected_results"):
            value = failure_fields(error).get(key)
            if value is not None:
                failure[key] = value
        from runtime.assessment_jobs import _job_id

        return {
            "job_id": _job_id(role, selector),
            "role": role,
            "selector": selector,
            "subject": "component" if component.get("name") else "repository",
            "label": message(label),
            "batch": f"{batch[1]} of {batch[2]}" if batch else None,
            "outcome": outcome,
            "recorded": _now(),
            "request_sha256": calls.request_sha256 if calls is not None else None,
            "failure": failure,
            "trail": trail,
            "calls": rows,
        }

    def _document(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "kind": "appsec-analyzer failed analysis jobs",
            "reading_guide": READING_GUIDE,
            "written": _now(),
            "run": self.run,
            "jobs": self.jobs,
            "instructions": self.instructions,
            "schemas": {key: json.loads(value) for key, value in self.schemas.items()},
            "code": self.code,
        }

    def _write(self) -> None:
        info = self.directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise OSError("debug directory must be private and owned")
        while True:
            changed = [0]
            document = _masked(self._document(), changed)
            document["masked_values"] = changed[0]
            data = json.dumps(document, ensure_ascii=False, indent=1, allow_nan=False).encode()
            inline = [job for job in self.jobs if "calls" in job and job["calls"]]
            if len(data) <= MAX_FILE_BYTES or not inline:
                break
            # The largest job's calls move complete into their own file; nothing is shortened.
            job = max(inline, key=lambda row: len(json.dumps(row["calls"], ensure_ascii=False)))
            name = f"{Path(FILE_NAME).stem}.{job['job_id']}.json"
            changed = [0]
            calls = _masked({"schema_version": SCHEMA_VERSION, "job_id": job["job_id"], "calls": job["calls"]}, changed)
            self._replace(self.directory / name, json.dumps(calls, ensure_ascii=False, indent=1).encode())
            job["calls_file"] = name
            job["call_count"] = len(job.pop("calls"))
        self._replace(self.path, data)

    def _replace(self, path: Path, data: bytes) -> None:
        fd, temporary = tempfile.mkstemp(prefix=".tmp-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
            os.replace(temporary, path)
        except BaseException:
            Path(temporary).unlink(missing_ok=True)
            raise


def run_identity(*, run_id, attempt_id, runtime_sha256, depth, run_profile, cfg, api_profile, inventory) -> dict:
    """What the debug file names about the run, with explicitly selected fields only (no connection settings)."""
    from appsec_analyzer import ENGINE_VERSION, INTERFACE_VERSION
    from appsec_analyzer.model_roles import RENDERER_MODEL_KEYS, SEMANTIC_ROLE_MODEL_KEYS

    try:
        from importlib.metadata import PackageNotFoundError, version

        package = version("appsec-analyzer")
    except (ImportError, PackageNotFoundError):
        package = None
    models = {
        role: {"model": cfg[key]}
        for role, key in {**SEMANTIC_ROLE_MODEL_KEYS, **RENDERER_MODEL_KEYS}.items()
        if isinstance(cfg.get(key), str)
    }
    profile = None
    if run_profile:
        profile = {"name": run_profile.get("name"), "adapter": run_profile.get("adapter")}
        for role, settings in (run_profile.get("models") or {}).items():
            if isinstance(settings, dict):
                models[role] = {key: settings.get(key) for key in ("model", "reasoning_effort") if settings.get(key)}
    elif api_profile is not None:
        profile = {"adapter": getattr(api_profile, "kind", None), "model": getattr(api_profile, "model", None)}
    return {
        "run_id": run_id,
        "attempt_id": attempt_id,
        "analyzer": {
            "package_version": package,
            "engine_version": ENGINE_VERSION,
            "interface_version": INTERFACE_VERSION,
            "runtime_sha256": runtime_sha256,
        },
        "depth": depth,
        "profile": profile,
        "models": models,
        "sources": [
            {
                key: row.get(key)
                for key in ("repository_id", "label", "head", "dirty", "without_git")
                if row.get(key) is not None
            }
            for row in inventory.get("repositories", [])
        ],
    }
