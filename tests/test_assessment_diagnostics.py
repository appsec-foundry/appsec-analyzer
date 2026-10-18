"""Full assessments retain correlated diagnostics without retaining model inputs."""

import json
from concurrent.futures import ThreadPoolExecutor

import pytest
from runtime import assessment_diagnostics as diagnostics
from runtime.analyst_host import HostReply, TransportError
from runtime.assessment_host import ExchangeError

from tests.test_assessment_jobs import setup


def records(log):
    return [json.loads(line) for line in log.path.read_text().splitlines()]


def test_parallel_calls_keep_job_identity_and_never_log_inputs_or_answers(tmp_path):
    log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")

    class Host:
        def invoke(self, *args):
            return HostReply({"private_answer": "MODEL_CONTENT"}, 0.01)

    def call(number):
        log.job("stride_analyzer", f"component-{number}").wrap(Host()).invoke(
            "PRIVATE_SYSTEM", "PRIVATE_SOURCE", {"private_schema": True}, 5, lambda: False
        )

    with ThreadPoolExecutor(max_workers=4) as workers:
        list(workers.map(call, range(12)))
    rows = records(log)
    starts = [row for row in rows if row["event"] == "call_start"]
    assert len({row["call_id"] for row in starts}) == 12
    assert len({row["job_id"] for row in starts}) == 12
    for start in starts:
        end = next(row for row in rows if row["event"] == "call_returned" and row["call_id"] == start["call_id"])
        assert end["job_id"] == start["job_id"] and end["selector"] == start["selector"]
        assert end["run_id"] == "assessment-test" and end["attempt_id"] == log.directory.name
    text = log.path.read_text()
    assert not any(value in text for value in ("PRIVATE_", "MODEL_CONTENT", "private_schema", "private_answer"))
    assert log.directory.stat().st_mode & 0o777 == 0o700
    assert log.path.stat().st_mode & 0o777 == 0o600


def test_required_failure_retains_selector_role_and_long_rejection(tmp_path):
    reason = "Evidence validation: " + "missing anchor; " * 15 + "threats/4/evidence/line: not executable"

    def reject(*args):
        raise ExchangeError(reason)

    reply = {"action": "complete", "reads": [], "artifact": {"result": "not accepted"}}
    jobs, _, kwargs, _ = setup(tmp_path, replies=[reply] * 3, validate=reject)
    jobs.diagnostics = log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")
    kwargs["selector"] = "component-gateway"
    with pytest.raises(ExchangeError, match="architecture_analyst component-gateway") as caught:
        jobs.execute(**kwargs)
    assert caught.value.attempts == 3
    assert str(caught.value.rejection) == reason
    assert caught.value.assessment_job["selector"] == "component-gateway"
    assert caught.value.diagnostic_path == log.path
    rows = records(log)
    rejections = [row for row in rows if row["event"] == "answer_rejected"]
    assert len(rejections) == 2 and all(reason == row["detail"] for row in rejections)
    assert rows[-1]["event"] == "job_failed" and reason in rows[-1]["detail"]
    assert rows[-1]["exchanges"] == 3 and rows[-1]["source_read_rounds"] == 0
    assert rows[-1]["rejected_results"] == 3
    assert not list(jobs.directory.glob("*.receipt.json"))


def test_accepted_and_reused_jobs_share_receipt_identity(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.diagnostics = log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")
    jobs.execute(**kwargs)
    jobs.execute(**kwargs)
    receipt = json.loads(next(jobs.directory.glob("*.receipt.json")).read_text())
    rows = records(log)
    assert host.calls == 1
    assert rows[-1]["event"] == "job_reused"
    assert all(row["job_id"] == receipt["job_id"] for row in rows if "job_id" in row)
    assert any(row["event"] == "job_accepted" for row in rows)


def test_optional_model_failure_is_recorded_as_replacement(tmp_path):
    reply = {"action": "complete", "reads": [], "artifact": {"result": "not accepted"}}

    def reject(*args):
        raise ExchangeError("Evidence is missing")

    jobs, _, kwargs, _ = setup(tmp_path, replies=[reply] * 3, validate=reject)
    jobs.diagnostics = log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")
    assert jobs.execute(**kwargs, on_failure=lambda reason: {"result": "fallback"}) == {"result": "fallback"}
    assert records(log)[-1]["event"] == "job_replaced"
    assert not list(jobs.directory.glob("*.receipt.json"))


@pytest.mark.parametrize(
    "reason",
    [
        "host_arguments",
        "invalid_response_stream",
        "invalid_response_envelope",
        "invalid_response_payload",
        "unexpected_host_item",
        "incomplete_response",
    ],
)
def test_host_failure_logs_fixed_classification_and_exit_code_without_raw_text(tmp_path, reason):
    log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")

    class Host:
        def invoke(self, *args):
            raise TransportError("RAW_PROVIDER_SECRET", reason=reason, exit_code=7)

    with pytest.raises(TransportError):
        log.job("recon_scanner", "discovery").wrap(Host()).invoke("s", "p", {}, 5, lambda: False)
    row = records(log)[-1]
    assert row["reason"] == reason and row["exit_code"] == 7
    assert "RAW_PROVIDER_SECRET" not in log.path.read_text()


def test_verbose_corrections_keep_job_call_identity_and_the_detailed_reason(tmp_path):
    from orchestrator.orchestration_controller import _AssessmentConsole, _ReportedTransport

    lines = []
    console = _AssessmentConsole(True, write=lines.append, live=False)
    console.step("Analyzing all STRIDE categories: Gateway (1/1)")
    trace = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test").job(
        "stride_analyzer", "component-gateway"
    )
    transport = trace.wrap(
        _ReportedTransport(object(), lambda text: console.call(text, "stride_analyzer", "reviewed-model"))
    )
    detail = "Missing evidence: " + "check source range; " * 12 + "threats/5/evidence/line is blank"
    transport.on_correction(detail)
    text = "\n".join(lines)
    assert "component-gateway" in text and "call-000001" in text and trace.fields["job_id"] in text
    assert "threats/5/evidence/line is blank" in text
    assert console.corrections["STRIDE"] == 1


def test_required_transport_failure_keeps_recovery_advice_and_accounting(tmp_path):
    jobs, host, kwargs, _ = setup(tmp_path)
    jobs.diagnostics = log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")

    def fail(*args):
        raise TransportError("RAW_PROVIDER_SECRET", reason="authentication_failed", usd=0, exit_code=1, http_status=401)

    host.invoke = fail
    with pytest.raises(TransportError) as caught:
        jobs.execute(**kwargs)
    assert caught.value.reason == "authentication_failed" and caught.value.exit_code == 1
    assert caught.value.usd == 0
    assert caught.value.http_status == 401
    assert "/login" in str(caught.value) and "--resume" in str(caught.value)
    assert "architecture_analyst one" in str(caught.value)
    assert "RAW_PROVIDER_SECRET" not in str(caught.value) + log.path.read_text()
    assert records(log)[-1]["http_status"] == 401


@pytest.mark.parametrize("error", [OSError("PRIVATE_LOCATION"), RuntimeError("PRIVATE_INTERNAL_VALUE")])
def test_unexpected_failures_never_log_raw_exception_text(tmp_path, error):
    log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")

    class Host:
        def invoke(self, *args):
            raise error

    with pytest.raises(type(error)):
        log.job("stride_analyzer", "component-gateway").wrap(Host()).invoke("s", "p", {}, 5, lambda: False)
    assert records(log)[-1]["reason"] == "internal_error"
    assert "PRIVATE_" not in log.path.read_text()


def test_reasons_keep_structural_detail_and_remove_values_locations_and_control_codes():
    raw = "threats/4/evidence: expected 'PRIVATE_SOURCE' at /home/user/private/file.py; password='synthetic-secret-123'\n\x1b[2J FORGED"
    cleaned = diagnostics.safe_reason(raw)
    assert cleaned.startswith("threats/4/evidence: expected")
    assert all(value not in cleaned for value in ("PRIVATE_SOURCE", "/home/user", "synthetic-secret-123", "\n", "\x1b"))
    assert "[value]" in cleaned and "[location]" in cleaned
    assert diagnostics.identifier("component\nFORGED") != "component\nFORGED"
    assert diagnostics.identifier("/private/location").startswith("id-")


def test_oversized_rejection_marks_truncation_and_keeps_the_tail():
    reason = diagnostics.safe_reason("start " + "invalid anchor; " * 600 + "decisive final violation")
    assert "[reason truncated]" in reason and reason.endswith("decisive final violation")
    assert len(reason) < diagnostics.MAX_REASON + 100


def test_multiline_quoted_values_and_oversized_inputs_cannot_leak_fragments():
    assert "PRIVATE" not in diagnostics.safe_reason("evidence invalid: 'PRIVATE\nSOURCE' violates the rule")
    assert "PRIVATE" not in diagnostics.safe_reason("evidence invalid: 'PRIVATE\"VALUE' violates the rule")
    huge = diagnostics.safe_reason("PRIVATE_SOURCE" * 3000)
    assert "PRIVATE" not in huge and "[reason truncated]" in huge


def test_resume_attempts_preserve_earlier_records(tmp_path):
    first = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")
    first.emit("attempt_failed", reason="timeout")
    before = first.path.read_bytes()
    resumed = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")
    assert first.path != resumed.path and first.path.read_bytes() == before


@pytest.mark.parametrize(
    "kind,event,reason",
    [
        ("cancel", "attempt_interrupted", "cancelled"),
        ("pause", "attempt_interrupted", "paused"),
        ("timeout", "attempt_failed", "timeout"),
    ],
)
def test_session_distinguishes_operator_stops_from_model_failures(tmp_path, kind, event, reason):
    from orchestrator import orchestration_controller as controller
    from runtime.analyst_host import HostCancelled, HostTimeout
    from runtime.assessment_jobs import AssessmentBudget
    from runtime.assessment_state import AssessmentPaused
    from runtime.multi_repo_scope import admit

    from tests.test_multi_repo_controller import checkout

    roots = [tmp_path / "caller", tmp_path / "receiver"]
    for root in roots:
        checkout(root)
    scope = admit([str(root) for root in roots], str(tmp_path / "out"))
    error = {
        "cancel": HostCancelled("cancelled"),
        "pause": AssessmentPaused(1, 8, "Reconnaissance"),
        "timeout": HostTimeout("model call exceeded its time limit"),
    }[kind]
    with pytest.raises(type(error)):
        with controller._assessment_session(
            scope,
            ["--no-requirements"],
            budget=AssessmentBudget(2, 0.05, 60, 3600),
            host_factory=lambda *args: pytest.fail("This lifecycle check must not dispatch a model call"),
            model="haiku",
        ) as (_cfg, _state, jobs):
            log = jobs.diagnostics
            raise error
    assert records(log)[-1]["event"] == event and records(log)[-1]["reason"] == reason


def test_linked_diagnostic_directory_is_refused(tmp_path):
    external = tmp_path / "external"
    external.mkdir()
    linked = tmp_path / "diagnostics"
    linked.symlink_to(external, target_is_directory=True)
    with pytest.raises(OSError):
        diagnostics.DiagnosticLog(linked, "assessment-test")
    assert list(external.iterdir()) == []


def test_log_limit_warns_once_and_never_stops_model_work(tmp_path, monkeypatch, capsys):
    log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")
    before = log.path.read_bytes()
    monkeypatch.setattr(diagnostics, "MAX_LOG_BYTES", len(before))
    log.emit("call_start")
    log.emit("call_start")
    assert log.path.read_bytes() == before
    assert capsys.readouterr().err.count("diagnostics disabled") == 1


def test_replaced_log_link_cannot_write_to_another_file(tmp_path, capsys):
    log = diagnostics.DiagnosticLog(tmp_path / "diagnostics", "assessment-test")
    external = tmp_path / "external"
    external.write_text("unchanged")
    log.path.unlink()
    log.path.symlink_to(external)
    log.emit("call_start")
    assert external.read_text() == "unchanged"
    assert "diagnostics disabled" in capsys.readouterr().err
