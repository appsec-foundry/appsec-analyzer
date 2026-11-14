"""REQ-050: a failed analysis job leaves one private debug file with everything needed to find its cause."""

import io
import json
import stat

import pytest
from runtime import assessment_diagnostics as diagnostics
from runtime import failure_debug
from runtime.analyst_host import HostCancelled, TransportError
from runtime.assessment_host import ExchangeError, ModelAnswerFailure

from tests.test_assessment_jobs import setup

TOKEN = "ghp_" + "A1b2" * 9
REJECTED = {"action": "complete", "reads": [], "artifact": {"result": "not accepted"}}


def debugged(tmp_path, **options):
    jobs, host, kwargs, checkpoints = setup(tmp_path, **options)
    jobs.diagnostics = log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")
    jobs.failure_debug = failure_debug.FailureDebug(log.directory, {"run_id": "assessment-test"})
    return jobs, host, kwargs, log


def document(log):
    path = log.directory / failure_debug.FILE_NAME
    return json.loads(path.read_text(encoding="utf-8"))


def test_stopped_job_keeps_every_request_answer_rejection_and_check_code(tmp_path):
    reason = "Evidence validation: threats/0/evidence/line: not executable"

    def reject(*args):
        raise ExchangeError(reason)

    jobs, _, kwargs, log = debugged(tmp_path, replies=[REJECTED] * 3, validate=reject)
    kwargs["selector"] = "component-gateway:2/3"
    kwargs["context"] = {"component": {"name": "Gateway"}}
    with pytest.raises(ModelAnswerFailure) as caught:
        jobs.execute(**kwargs)
    assert caught.value.attempts == 3
    path = log.directory / failure_debug.FILE_NAME
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    data = document(log)
    job = data["jobs"][0]
    assert (job["role"], job["selector"], job["label"], job["batch"]) == (
        "architecture_analyst",
        "component-gateway:2/3",
        "Gateway",
        "2 of 3",
    )
    assert job["outcome"] == "stopped the run" and job["request_sha256"]
    assert job["failure"]["type"] == "ModelAnswerFailure" and job["failure"]["code"] == "validation"
    assert job["failure"]["rejected_results"] == 3
    # The full rejection, not the shortened console form.
    assert reason in job["failure"]["message"]
    calls = job["calls"]
    assert len(calls) == 3
    assert all(call["answer"] == REJECTED and call["rejection"] == reason for call in calls)
    assert all(call["instructions_sha256"] in data["instructions"] for call in calls)
    assert all(call["schema_sha256"] in data["schemas"] for call in calls)
    assert "trusted" in data["instructions"][calls[0]["instructions_sha256"]]
    assert all("source_slices" in call["prompt"] for call in calls)
    # Each rejection names the Analyzer check, and the file carries that check's code.
    assert [entry["corrections"] for entry in job["trail"]] == [["full correction"], ["full correction"], []]
    check = job["trail"][0]["check"]
    assert "assessment_jobs.py" in check
    assert "validate(artifact, ranges)" in data["code"][check]["code"]
    assert data["reading_guide"] and data["masked_values"] == 0


def test_replaced_job_is_recorded_and_the_run_goes_on(tmp_path):
    def reject(*args):
        raise ExchangeError("Evidence is missing")

    jobs, _, kwargs, log = debugged(tmp_path, replies=[REJECTED] * 3, validate=reject)
    assert jobs.execute(**kwargs, on_failure=lambda reason: {"result": "fallback"}) == {"result": "fallback"}
    assert jobs.failure_debug.written
    job = document(log)["jobs"][0]
    assert job["outcome"].startswith("replaced") and len(job["calls"]) == 3


def test_stopped_call_keeps_code_timing_retries_and_a_masked_host_message(tmp_path):
    jobs, host, kwargs, log = debugged(tmp_path)

    def fail(*args):
        raise TransportError(f"host said: login rejected for {TOKEN}", reason="authentication_failed", usd=0)

    host.invoke = fail
    with pytest.raises(TransportError):
        jobs.execute(**kwargs)
    text = (log.directory / failure_debug.FILE_NAME).read_text(encoding="utf-8")
    assert TOKEN not in text
    data = json.loads(text)
    call = data["jobs"][0]["calls"][0]
    assert call["failure"]["code"] == "authentication_failed" and "seconds" in call
    assert "login rejected" in call["failure"]["message"] and "answer" not in call
    assert data["masked_values"] >= 1
    # The shared feed still keeps no host text.
    assert "login rejected" not in log.path.read_text()


def test_masked_answers_keep_their_shape(tmp_path):
    answer = {"action": "complete", "reads": [], "artifact": {"result": f"key {TOKEN}"}}

    def reject(*args):
        raise ExchangeError("Evidence is missing")

    jobs, _, kwargs, log = debugged(tmp_path, replies=[answer] * 3, validate=reject)
    with pytest.raises(ModelAnswerFailure):
        jobs.execute(**kwargs)
    text = (log.directory / failure_debug.FILE_NAME).read_text(encoding="utf-8")
    assert TOKEN not in text
    assert json.loads(text)["jobs"][0]["calls"][0]["answer"]["artifact"]["result"].startswith("key ")


def test_accepted_cancelled_and_budget_stopped_jobs_write_no_debug_file(tmp_path):
    from runtime.multi_repo_discovery import BudgetExhausted

    jobs, host, kwargs, log = debugged(tmp_path)
    jobs.execute(**kwargs)
    for error in (HostCancelled("stopped by the user"), BudgetExhausted("limit reached")):
        kwargs["selector"] = type(error).__name__

        def fail(*args, error=error):
            raise error

        host.invoke = fail
        with pytest.raises(type(error)):
            jobs.execute(**kwargs)
    assert not jobs.failure_debug.written
    assert not (log.directory / failure_debug.FILE_NAME).exists()


def test_oversized_calls_move_complete_into_their_own_file(tmp_path, monkeypatch):
    long_answer = {"action": "complete", "reads": [], "artifact": {"result": "x" * 50_000}}

    def reject(*args):
        raise ExchangeError("Evidence is missing")

    monkeypatch.setattr(failure_debug, "MAX_FILE_BYTES", 40_000)
    jobs, _, kwargs, log = debugged(tmp_path, replies=[long_answer] * 3, validate=reject)
    with pytest.raises(ModelAnswerFailure):
        jobs.execute(**kwargs)
    job = document(log)["jobs"][0]
    assert "calls" not in job and job["call_count"] == 3
    side = log.directory / job["calls_file"]
    assert stat.S_IMODE(side.stat().st_mode) == 0o600
    calls = json.loads(side.read_text(encoding="utf-8"))["calls"]
    assert all(call["answer"] == long_answer for call in calls)


def test_debug_file_refuses_a_shared_directory(tmp_path, capsys):
    def reject(*args):
        raise ExchangeError("Evidence is missing")

    jobs, _, kwargs, log = debugged(tmp_path, replies=[REJECTED] * 3, validate=reject)
    log.directory.chmod(0o755)
    with pytest.raises(ModelAnswerFailure):
        jobs.execute(**kwargs)
    assert not (log.directory / failure_debug.FILE_NAME).exists()
    assert jobs.failure_debug.disabled and "debug file unavailable" in capsys.readouterr().err


@pytest.mark.parametrize(
    "location",
    [
        "read (../../outside.py:1)",
        "read (/etc/hosts.py:1)",
        "read (scripts/runtime/missing_module.py:3)",
        "exchange envelope",
        "",
    ],
)
def test_check_code_stays_inside_the_installation(tmp_path, location):
    from pathlib import Path

    import appsec_analyzer

    root = Path(appsec_analyzer.__file__).resolve().parent.parent
    assert failure_debug._check_code(location, root) is None


def test_run_identity_names_versions_models_and_sources_without_connection_settings():
    run_profile = {
        "name": "standard",
        "adapter": "lite",
        "models": {"stride_analyzer": {"model": "m-large", "reasoning_effort": "high", "api_key_env": "SECRET_ENV"}},
    }
    inventory = {
        "repositories": [
            {"repository_id": "repo-1", "label": "app", "head": "a" * 40, "dirty": False, "files": [{"path": "x"}]}
        ]
    }
    identity = failure_debug.run_identity(
        run_id="assessment-1",
        attempt_id="attempt-x",
        runtime_sha256="f" * 64,
        depth="standard",
        run_profile=run_profile,
        cfg={},
        api_profile=None,
        inventory=inventory,
    )
    assert identity["models"]["stride_analyzer"] == {"model": "m-large", "reasoning_effort": "high"}
    assert identity["sources"] == [{"repository_id": "repo-1", "label": "app", "head": "a" * 40, "dirty": False}]
    assert identity["analyzer"]["engine_version"] and identity["analyzer"]["runtime_sha256"] == "f" * 64
    assert "SECRET_ENV" not in json.dumps(identity)


def test_stop_and_completion_messages_name_the_debug_file(tmp_path, monkeypatch):
    from orchestrator import orchestration_controller as controller
    from renderers.term_style import Style

    monkeypatch.setattr(controller._RunDebug, "path", "/private/out/failed-jobs.json")
    stream = io.StringIO()
    controller._stop("✗ Assessment stopped", ("Reason", "stopped"), stream=stream)
    assert "Debug file" in stream.getvalue() and "/private/out/failed-jobs.json" in stream.getvalue()
    monkeypatch.setattr(controller._RunDebug, "path", None)
    stream = io.StringIO()
    controller._stop("✗ Assessment stopped", ("Reason", "stopped"), stream=stream)
    assert "Debug file" not in stream.getvalue()
    outcome = dict(
        repositories=["demo"],
        output=str(tmp_path),
        deliverables=["security-assessment.md"],
        calls=1,
        spent_usd=0.1,
        debug_file="/private/out/failed-jobs.json",
    )
    stream = io.StringIO()
    controller._print_completion(outcome, "1m", Style(False), stream)
    assert "Debug file" in stream.getvalue()


class FrozenError(ValueError):
    """Like jsonschema's errors, it refuses new attributes."""

    def __setattr__(self, name, value):
        if name.startswith("__"):
            return super().__setattr__(name, value)
        raise AttributeError(name)


def test_session_names_the_debug_file_and_keeps_the_error_that_stops_the_run(tmp_path, monkeypatch):
    from orchestrator import orchestration_controller as controller
    from runtime.assessment_jobs import AssessmentBudget
    from runtime.multi_repo_scope import admit

    from tests.test_multi_repo_controller import checkout

    monkeypatch.setattr(controller._RunDebug, "path", "/earlier/run/failed-jobs.json")
    roots = [tmp_path / "caller", tmp_path / "receiver"]
    for root in roots:
        checkout(root)
    scope = admit([str(root) for root in roots], str(tmp_path / "out"))
    error = FrozenError("stopped")
    with pytest.raises(FrozenError) as caught:
        with controller._assessment_session(
            scope,
            ["--no-requirements"],
            budget=AssessmentBudget(2, 0.05, 60, 3600),
            host_factory=lambda *args: pytest.fail("This lifecycle check must not dispatch a model call"),
            model="haiku",
        ) as (_cfg, _state, jobs):
            debug = jobs.failure_debug
            # A new session never names an earlier run's file.
            assert controller._RunDebug.path is None
            assert debug.run["sources"] and debug.run["analyzer"]["runtime_sha256"]
            debug.record(
                None, ExchangeError("check failed"), outcome="stopped the run", role="r", selector="s", context={}
            )
            raise error
    # The run's own error ends it unchanged, and the stop message can still name the file.
    assert caught.value is error
    assert controller._RunDebug.path == str(debug.path)
    assert debug.path.parent == jobs.diagnostics.directory


def test_session_without_a_failed_job_names_no_debug_file(tmp_path, monkeypatch):
    from orchestrator import orchestration_controller as controller
    from runtime.assessment_jobs import AssessmentBudget
    from runtime.multi_repo_scope import admit

    from tests.test_multi_repo_controller import checkout

    monkeypatch.setattr(controller._RunDebug, "path", None)
    roots = [tmp_path / "caller", tmp_path / "receiver"]
    for root in roots:
        checkout(root)
    scope = admit([str(root) for root in roots], str(tmp_path / "out"))
    with pytest.raises(ValueError):
        with controller._assessment_session(
            scope,
            ["--no-requirements"],
            budget=AssessmentBudget(2, 0.05, 60, 3600),
            host_factory=lambda *args: pytest.fail("This lifecycle check must not dispatch a model call"),
            model="haiku",
        ) as (_cfg, _state, jobs):
            raise ValueError("stopped")
    assert controller._RunDebug.path is None
    assert not jobs.failure_debug.path.exists()
