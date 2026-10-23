"""Assessment ownership, unchanged-state resume and retained cost reservations."""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from contextlib import nullcontext
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from runtime import acquire_lock
from runtime.analyst_host import HostCancelled, HostReply, TransportError
from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
from runtime.assessment_state import CACHE_NAME, STOP_NAME, AssessmentState
from runtime.multi_repo_scope import AssessmentScope, ScopeError, admit


@pytest.fixture
def scope(tmp_path):
    roots = []
    for label in ("frontend", "backend"):
        root = tmp_path / label
        root.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(root)], check=True)
        (root / "app.py").write_text("print('neutral fixture')\n")
        subprocess.run(["git", "-C", str(root), "add", "app.py"], check=True)
        subprocess.run(
            [
                "git",
                "-C",
                str(root),
                "-c",
                "user.name=Fixture",
                "-c",
                "user.email=fixture@example.invalid",
                "-c",
                "commit.gpgsign=false",
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "Fixture",
            ],
            check=True,
        )
        roots.append(str(root))
    return admit(roots, str(tmp_path / "reports"))


def lifecycle(scope, **overrides):
    options = {
        "configuration": {"stride_model": "haiku"},
        "runtime_sha256": "a" * 64,
        "budget": AssessmentBudget(1.0, 0.05, 10, 60),
    }
    options.update(overrides)
    return AssessmentState(scope, **options)


def stored(scope):
    return json.loads((scope.output / ".assessment-state.json").read_text())


def test_budget_report_is_incomplete_redacted_and_resumable(scope):
    from types import SimpleNamespace

    from runtime.multi_repo_discovery import BudgetExhausted

    state = lifecycle(scope)
    state.budget.plan_completion()
    repo = scope.repositories[0]
    jobs = SimpleNamespace(
        accepted_results={
            "stride:example": {
                "role": "stride_analyzer",
                "selector": "stride:example",
                "finding_count": 1,
                "findings": [
                    {
                        "title": "<img src=x> [click](https://example.invalid) neutral fixture",
                        "repository_id": repo.repository_id,
                        "file": "app.py",
                        "line": 1,
                    }
                ],
            }
        }
    )
    with pytest.raises(BudgetExhausted), state.hold():
        path = state.budget_report(jobs)
        text = path.read_text()
        assert "Incomplete assessment" in text and "not a completed threat model" in text
        assert "neutral fixture" not in text and "REDACTED" in text
        assert "<img" not in text and "[click](" not in text
        assert not (scope.output / "threat-model.md").exists()
        raise BudgetExhausted("cost limit")
    assert stored(scope)["status"] == "interrupted"
    assert stored(scope)["partial_report"]["status"] == "incomplete"
    assert stored(scope)["deliverables"] == {}
    with lifecycle(scope, resume=True).hold():
        pass


@pytest.mark.parametrize("invalid", ["scope", "accounting", "cancelled", "contract"])
def test_budget_report_refuses_invalid_security_context(scope, invalid):
    from types import SimpleNamespace

    state = lifecycle(scope)
    with state.hold():
        jobs = SimpleNamespace(accepted_results={})
        if invalid == "scope":
            (scope.repositories[0].root / "app.py").write_text("print('changed')\n")
        elif invalid == "accounting":
            state.budget.failed = True
        elif invalid == "cancelled":
            state.cancelled = True
        else:
            jobs.accepted_results["bad"] = {
                "selector": "bad",
                "role": "stride_analyzer",
                "finding_count": 1,
                "findings": [{"title": "bad", "repository_id": "foreign", "file": "a", "line": 0}],
            }
        from jsonschema import ValidationError

        with pytest.raises((ExchangeError, ScopeError, ValidationError)):
            state.budget_report(jobs)
        assert not (state.directory / "budget-report.md").exists()


def test_interrupted_session_releases_lock_and_resumes_same_identity(scope):
    initial = lifecycle(scope)
    with initial.hold():
        assert acquire_lock.read_run_id(initial.lock) == initial.state["run_id"]
        initial.budget.calls, initial.budget.spent_usd = 2, 0.03
        initial.checkpoint()
    assert not initial.lock.exists()
    assert stored(scope)["status"] == "interrupted"
    resumed = lifecycle(scope, resume=True)
    with resumed.hold():
        assert resumed.state["run_id"] == initial.state["run_id"]
        assert resumed.budget.calls == 2 and resumed.budget.spent_usd == 0.03
        assert resumed.budget.deadline <= initial.budget.deadline + 1


def test_budget_holds_are_never_persisted_and_start_empty_on_resume(scope):
    initial = lifecycle(scope)
    with initial.hold():
        initial.budget.hold("open-review", 0.5, 3)
        initial.budget.calls, initial.budget.spent_usd = 1, 0.01
        initial.checkpoint()
        assert "hold" not in json.dumps(stored(scope))
        assert stored(scope)["accounting"].keys() == {"calls", "spent_usd", "unavailable"}
    # The controller recomputes holds for a resumed run.
    resumed = lifecycle(scope, resume=True)
    with resumed.hold():
        assert resumed.budget.holds == {} and resumed.budget.calls == 1


def test_worked_time_continues_across_attempts_without_the_pause_between_them(scope, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    with lifecycle(scope).hold():
        clock[0] += 30
    assert stored(scope)["worked_seconds"] == 30
    # The pause before the resume does not count.
    clock[0] += 3600
    resumed = lifecycle(scope, resume=True)
    with resumed.hold():
        assert resumed.worked_before == 30
        clock[0] += 12
    assert stored(scope)["worked_seconds"] == 42
    fresh = lifecycle(scope)
    with fresh.hold():
        assert fresh.worked_before == 0


def test_approved_budget_is_persisted_before_use_and_restored_on_resume(scope):
    state = lifecycle(scope)
    with state.hold():
        state.approve_budget_increase(2.5)
        assert stored(scope)["budget_authorizations"][0]["max_usd"] == 2.5
        assert state.budget.max_usd == 2.5
        assert stored(scope)["identity"]["limits"]["max_usd"] == 1.0
        state.budget.spent_usd = 1.2
    resumed = lifecycle(scope, resume=True)
    with resumed.hold():
        assert resumed.budget.max_usd == 2.5 and resumed.budget.spent_usd == 1.2


@pytest.mark.parametrize("answer,expected_calls", [("2.00\n", 1), ("\n", 0)])
def test_explicit_terminal_answer_controls_admission_and_persistence(scope, monkeypatch, answer, expected_calls):
    from runtime.interactive_budget import BudgetPrompt

    state = lifecycle(scope)
    with state.hold():
        state.budget.spent_usd = 0.97
        prompt = BudgetPrompt(state, report=lambda text: None, pause=lambda value: None, role_labels={})
        monkeypatch.setattr(prompt, "_readline", lambda stop: answer)
        state.budget.on_budget_increase = prompt

        class Host:
            def invoke(self, *args):
                assert stored(scope)["budget_authorizations"][-1]["max_usd"] == 2.0
                return HostReply({"action": "complete", "reads": [], "artifact": {"ok": True}}, 0.01)

        jobs = AssessmentJobs(
            scope,
            state.directory / "jobs",
            state.budget,
            lambda role, ceiling: Host(),
            state.should_stop,
            state.checkpoint,
        )
        result = jobs.execute(
            role="architect_reviewer",
            selector="test",
            instructions="trusted",
            context={},
            schema={"type": "object", "required": ["ok"]},
            allowed_sources=frozenset(),
            validate=lambda artifact, ranges: None,
            on_failure=lambda reason: {"ok": False},
        )
        assert result["ok"] == bool(expected_calls)
        assert state.budget.calls == expected_calls
        assert bool(stored(scope).get("budget_authorizations")) == bool(expected_calls)


@pytest.mark.parametrize("amount", [0, 1.0, -1, float("nan"), float("inf"), True, "2"])
def test_budget_approval_rejects_invalid_or_non_increasing_limits(scope, amount):
    state = lifecycle(scope)
    with state.hold():
        with pytest.raises(ExchangeError, match="budget increase"):
            state.approve_budget_increase(amount)
        assert state.budget.max_usd == 1.0 and not state.state.get("budget_authorizations")


def test_failed_approval_persistence_never_authorizes_spending(scope, monkeypatch):
    state = lifecycle(scope)
    with state.hold():
        with monkeypatch.context() as patch:
            patch.setattr(state, "checkpoint", lambda: (_ for _ in ()).throw(OSError("write failed")))
            with pytest.raises(OSError):
                state.approve_budget_increase(2.0)
        assert state.budget.max_usd == 1.0 and not state.state.get("budget_authorizations")


def test_resume_rejects_a_broken_budget_authorization_chain(scope):
    state = lifecycle(scope)
    with state.hold():
        state.approve_budget_increase(2.0)
    document = stored(scope)
    document["budget_authorizations"][0]["previous_max_usd"] = 0.5
    state.path.write_text(json.dumps(document))
    with pytest.raises(ExchangeError, match="authorization history"), lifecycle(scope, resume=True).hold():
        pass


@pytest.mark.parametrize("context", ["cancelled", "unsettled", "inflight"])
def test_budget_approval_requires_settled_active_work(scope, context):
    state = lifecycle(scope)
    with state.hold():
        if context == "cancelled":
            state.cancelled = True
        elif context == "unsettled":
            state.budget.failed = True
        else:
            state.budget._inflight = 1
        with pytest.raises(ExchangeError, match="budget increase"):
            state.approve_budget_increase(2.0)
        assert state.budget.max_usd == 1.0
        state.budget._inflight = 0


def test_complete_session_binds_deliverables_and_detects_later_changes(scope):
    state = lifecycle(scope)
    with state.hold():
        (scope.output / "threat-model.yaml").write_text("version: 2\n")
        state.complete(["threat-model.yaml"])
    assert stored(scope)["status"] == "complete"
    with lifecycle(scope, resume=True).hold() as resumed:
        assert resumed.state["status"] == "complete"
    (scope.output / "threat-model.yaml").write_text("version: modified\n")
    with pytest.raises(ExchangeError, match="changed after completion"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Altered deliverables must not be accepted")


@pytest.mark.parametrize(
    "field,value,named",
    [
        ("configuration", {"stride_model": "sonnet"}, "the assessment settings changed"),
        ("budget", AssessmentBudget(2.0, 0.05, 10, 60), "the budget or time limits changed"),
    ],
)
def test_changed_settings_reject_resume_and_name_the_change(scope, field, value, named):
    with lifecycle(scope).hold():
        pass
    with pytest.raises(
        ExchangeError, match=f"cannot resume: {named} .*new scan is required: run again without --resume"
    ) as caught:
        with lifecycle(scope, resume=True, **{field: value}).hold():
            pytest.fail("Changed request must not resume")
    assert "source code" not in str(caught.value)


def _plugin_change_jobs(state, host_factory):
    # As the controller does: every session may adopt cached jobs of an earlier unfinished run.
    return AssessmentJobs(
        state.scope,
        state.directory / "jobs",
        state.budget,
        host_factory,
        state.should_stop,
        state.checkpoint,
        cache=state.directory / CACHE_NAME,
    )


def test_runtime_change_refuses_resume_and_explicit_new_run_reuses_only_unchanged_jobs(scope):
    schema = {"type": "object", "required": ["ok"], "properties": {"ok": {"const": True}}}

    def job(selector, instructions):
        return dict(
            role="recon_scanner",
            selector=selector,
            instructions=instructions,
            context={},
            schema=schema,
            allowed_sources=frozenset(),
            validate=lambda a, r: None,
        )

    dispatched = []

    class Host:
        def __init__(self, role):
            self.role = role

        def invoke(self, *args):
            dispatched.append(self.role)
            return HostReply({"action": "complete", "reads": [], "artifact": {"ok": True}}, 0.01)

    first = lifecycle(scope)
    with first.hold():
        jobs = _plugin_change_jobs(first, lambda role, ceiling: Host(role))
        jobs.execute(**job("kept", "same prompt"))
        jobs.execute(**job("changed", "old prompt"))
    assert stored(scope)["status"] == "interrupted" and len(dispatched) == 2

    before = {p.relative_to(scope.output): p.read_bytes() for p in scope.output.rglob("*") if p.is_file()}
    with pytest.raises(ExchangeError, match="plugin version changed"):
        with lifecycle(scope, resume=True, runtime_sha256="b" * 64).hold():
            pytest.fail("Resume cannot authorize a new run or another budget")
    assert before == {p.relative_to(scope.output): p.read_bytes() for p in scope.output.rglob("*") if p.is_file()}
    assert len(dispatched) == 2

    resumed = lifecycle(scope, runtime_sha256="b" * 64)
    with resumed.hold():
        assert not resumed.resume
        assert resumed.state["run_id"] != first.state["run_id"]
        assert resumed.state["identity"]["runtime_sha256"] == "b" * 64
        jobs = _plugin_change_jobs(resumed, lambda role, ceiling: Host(role))
        jobs.execute(**job("kept", "same prompt"))
        jobs.execute(**job("changed", "new prompt"))
        assert len(dispatched) == 3  # only the job whose request changed ran again
        assert resumed.budget.calls == 2 and resumed.budget.spent_usd == pytest.approx(0.02)


@pytest.mark.parametrize("subscription", [False, True])
def test_runtime_change_cannot_reset_exhausted_resume_limits(scope, subscription):
    def budget():
        return (
            AssessmentBudget(None, None, 10, 60, subscription=True, spent_usd=None)
            if subscription
            else AssessmentBudget(1, 1, 10, 60)
        )

    configuration = (
        {"operator_profile": {"schema_version": 1, "definition_sha256": "a" * 64, "models": {}, "adapter": "codex-cli"}}
        if subscription
        else {}
    )
    first = lifecycle(scope, budget=budget(), configuration=configuration)
    with first.hold():
        first.budget.calls = 10
        if not subscription:
            first.budget.spent_usd = 1.0
    previous = stored(scope)
    previous["started_at"] -= 120
    previous["expires_at"] -= 120
    path = scope.output / ".assessment-state.json"
    path.write_text(json.dumps(previous))
    with pytest.raises(ExchangeError, match="plugin version changed"):
        with lifecycle(
            scope, budget=budget(), configuration=configuration, resume=True, runtime_sha256="b" * 64
        ).hold():
            pytest.fail("Runtime changes must not extend exhausted money, calls or deadlines")
    assert stored(scope) == previous


def test_resume_after_a_plugin_change_still_refuses_a_completed_run_or_unknown_cost(scope):
    with lifecycle(scope).hold() as state:
        (scope.output / "threat-model.yaml").write_text("version: 2\n")
        state.complete(["threat-model.yaml"])
    with pytest.raises(ExchangeError, match="the plugin version changed .*run again without --resume"):
        with lifecycle(scope, resume=True, runtime_sha256="b" * 64).hold():
            pytest.fail("A completed run must not be continued after a plugin change")
    # Unchanged plugin: a completed run still reopens as before.
    with lifecycle(scope, resume=True).hold() as reopened:
        assert not reopened.runtime_changed


def test_resume_after_a_plugin_change_keeps_unknown_cost_blocking(scope):
    with lifecycle(scope).hold():
        pass
    recorded = stored(scope)
    recorded["accounting"]["unavailable"] = True
    (scope.output / ".assessment-state.json").write_text(json.dumps(recorded))
    with pytest.raises(ExchangeError, match="the plugin version changed"):
        with lifecycle(scope, resume=True, runtime_sha256="b" * 64).hold():
            pytest.fail("Unknown costs must not be refunded by a plugin change")


def test_changed_source_cannot_resume_or_complete(scope):
    with lifecycle(scope).hold() as state:
        (scope.repositories[0].root / "app.py").write_text("print('changed')\n")
        (scope.output / "threat-model.yaml").write_text("version: 2\n")
        with pytest.raises(ScopeError, match="changed"):
            state.complete(["threat-model.yaml"])
    with pytest.raises(ScopeError, match="changed"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Changed source must not resume")


def test_cost_reservation_is_durable_before_dispatch_and_unknown_cost_blocks_resume(scope):
    state = lifecycle(scope)

    class BrokenHost:
        def invoke(self, *args):
            assert stored(scope)["accounting"] == {"calls": 1, "spent_usd": 0.05, "unavailable": True}
            raise RuntimeError("backend failed")

    with pytest.raises(RuntimeError, match="backend failed"):
        with state.hold():
            jobs = AssessmentJobs(
                scope,
                state.directory / "jobs",
                state.budget,
                lambda role, ceiling: BrokenHost(),
                state.should_stop,
                state.checkpoint,
            )
            jobs.execute(
                role="recon_scanner",
                selector="one",
                instructions="trusted",
                context={},
                schema={"type": "object"},
                allowed_sources=frozenset(),
                validate=lambda a, r: None,
            )
    assert stored(scope)["status"] == "failed"
    assert stored(scope)["accounting"]["unavailable"] is True
    with pytest.raises(ExchangeError, match="unfinished cost reservation"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Unknown costs must not be refunded")


def test_a_refused_call_with_a_reported_cost_leaves_the_run_resumable(scope):
    state = lifecycle(scope)

    class RefusingHost:
        def invoke(self, *args):
            raise TransportError("host call failed: authentication_failed", reason="authentication_failed", usd=0.0)

    with pytest.raises(TransportError, match="--resume"):
        with state.hold():
            AssessmentJobs(
                scope,
                state.directory / "jobs",
                state.budget,
                lambda role, ceiling: RefusingHost(),
                state.should_stop,
                state.checkpoint,
            ).execute(
                role="recon_scanner",
                selector="one",
                instructions="trusted",
                context={},
                schema={"type": "object"},
                allowed_sources=frozenset(),
                validate=lambda a, r: None,
            )
    assert stored(scope)["status"] == "failed"
    assert stored(scope)["accounting"] == {"calls": 1, "spent_usd": 0.0, "unavailable": False}
    with lifecycle(scope, resume=True).hold() as resumed:
        assert resumed.budget.calls == 1 and resumed.budget.spent_usd == 0.0


@pytest.mark.parametrize("rate_limit", [False, True])
def test_validated_cached_job_survives_resume_without_dispatch_or_extra_cost(scope, rate_limit):
    state = lifecycle(scope)
    schema = {
        "type": "object",
        "additionalProperties": False,
        "required": ["ok"],
        "properties": {"ok": {"const": True}},
    }
    kwargs = dict(
        role="recon_scanner",
        selector="one",
        instructions="trusted",
        context={},
        schema=schema,
        allowed_sources=frozenset(),
        validate=lambda a, r: None,
    )

    class Host:
        def invoke(self, *args):
            return HostReply({"action": "complete", "reads": [], "artifact": {"ok": True}}, 0.01)

    with pytest.raises(TransportError) if rate_limit else nullcontext(), state.hold():
        jobs = AssessmentJobs(
            scope,
            state.directory / "jobs",
            state.budget,
            lambda role, ceiling: Host(),
            state.should_stop,
            state.checkpoint,
        )
        assert jobs.execute(**kwargs) == {"ok": True}

        if rate_limit:
            raise TransportError("rate_limit", reason="rate_limit", usd=0)
    assert stored(scope)["status"] == "interrupted" and not state.lock.exists()
    assert stored(scope)["deliverables"] == {}

    def no_host(role, ceiling):
        pytest.fail("Accepted job must resume without another dispatch")

    with lifecycle(scope, resume=True).hold() as resumed:
        jobs = AssessmentJobs(
            scope, resumed.directory / "jobs", resumed.budget, no_host, resumed.should_stop, resumed.checkpoint
        )
        assert jobs.execute(**kwargs) == {"ok": True}
        assert resumed.budget.calls == 1 and resumed.budget.spent_usd == pytest.approx(0.01)


def test_existing_user_files_are_preserved_and_block_fresh_assessment(scope):
    scope.output.mkdir()
    original = scope.output / "notes.txt"
    original.write_text("preserve")
    with pytest.raises(ExchangeError, match="empty output"):
        with lifecycle(scope).hold():
            pytest.fail("Fresh assessment must not erase unrelated output")
    assert original.read_text() == "preserve"
    assert not (scope.output / ".assessment-state.json").exists()


def test_an_earlier_scans_run_diagnostics_never_block_a_fresh_assessment(scope):
    from runtime.assessment_state import RUN_DIAGNOSTIC_NAMES

    scope.output.mkdir()
    for name in RUN_DIAGNOSTIC_NAMES:
        (scope.output / name).write_text("{}")
    with lifecycle(scope).hold():
        pass
    # Only a run that holds the directory replaces them; the lifecycle itself keeps them.
    assert all((scope.output / name).is_file() for name in RUN_DIAGNOSTIC_NAMES)


@pytest.mark.parametrize("earlier", ["none", "completed"])
def test_session_hook_files_never_block_a_start(scope, earlier):
    """Hooks log, and the controller opens its progress feed, before the run holds the directory."""
    from runtime.assessment_state import PROGRESS_NAME, SESSION_HOOK_NAMES

    names = (*SESSION_HOOK_NAMES, PROGRESS_NAME)
    if earlier == "completed":
        _completed(scope)
    scope.output.mkdir(exist_ok=True)
    for name in names:
        (scope.output / name).write_text("hook\n")
    with lifecycle(scope).hold() as state:
        assert state.state["status"] == "running"
    # The earlier report stays until a new run completes.
    assert (scope.output / "threat-model.md").exists() is (earlier == "completed")
    assert all((scope.output / name).exists() for name in names)


def _fail(state):
    with pytest.raises(RuntimeError):
        with state.hold():
            (state.directory / "jobs").mkdir()
            (state.directory / "jobs" / "job-000000000000000000000000.json").write_text("{}")
            (state.directory / "context").mkdir()
            raise RuntimeError("stage failed")


@pytest.mark.parametrize("finish", ["failed", "interrupted"])
def test_fresh_start_clears_an_unfinished_run_but_keeps_its_job_cache(scope, finish):
    """Accepted jobs stay reusable; the job layer rechecks each against its new request."""
    first = lifecycle(scope)
    if finish == "failed":
        _fail(first)
    else:
        with first.hold():
            pass
    assert stored(scope)["status"] == finish
    if finish == "failed":
        (first.directory / "jobs" / "job-000000000000000000000000.receipt.json").write_text("{}")
        (first.directory / "jobs" / "job-111111111111111111111111.json").write_text("{}")
    with lifecycle(scope).hold() as fresh:
        assert fresh.state["run_id"] != first.state["run_id"]
        assert fresh.state["accounting"]["calls"] == 0
        assert not (fresh.directory / "context").exists()
        if finish == "failed":
            cached = {path.name for path in (fresh.directory / CACHE_NAME).iterdir()}
            # The accepted pair is cached; an artifact without a receipt was never accepted.
            assert cached == {"job-000000000000000000000000.json", "job-000000000000000000000000.receipt.json"}
            assert not (fresh.directory / "jobs").exists()


@pytest.mark.parametrize("rebuild", [False, True])
def test_resume_after_a_fresh_start_that_never_reached_a_cached_job(scope, rebuild):
    """A cached job a paused fresh start never reached stays out of the resume check.

    Without --rebuild a later session adopts it and charges its cost; with
    --rebuild it is gone and the job is redone.
    """
    _accept_job(scope, usd=0.02)
    with lifecycle(scope, replace=rebuild).hold():
        pass  # paused before the job was reached
    dispatched = []

    class Host:
        def invoke(self, *args):
            dispatched.append(args)
            return HostReply({"action": "complete", "reads": [], "artifact": {"ok": True}}, 0.03)

    with lifecycle(scope, resume=True).hold() as resumed:
        _plugin_change_jobs(resumed, lambda role, ceiling: Host()).execute(
            role="recon_scanner",
            selector="one",
            instructions="trusted",
            context={},
            schema={"type": "object"},
            allowed_sources=frozenset(),
            validate=lambda a, r: None,
        )
        assert len(dispatched) == (1 if rebuild else 0)
        assert resumed.budget.spent_usd == pytest.approx(0.03 if rebuild else 0.02)
    with lifecycle(scope, resume=True).hold():
        pass  # the adopted or redone receipt is covered by the accounting


# A completed run that owns every remaining file is replaced by a new scan
# (REQ-017); test_rebuild_keeps_a_directory_with_edited_or_foreign_files
# covers a completed run beside an edited or foreign file.
@pytest.mark.parametrize("extra", ["user-file", "malformed-state"])
def test_fresh_start_still_refuses_a_report_or_foreign_files(scope, extra):
    _fail(lifecycle(scope))
    preserved = scope.output / ".assessment-state.json"
    if extra == "user-file":
        preserved = scope.output / "notes.txt"
        preserved.write_text("preserve")
    else:
        preserved.write_text("not json")
    before = preserved.read_bytes()
    with pytest.raises(ExchangeError, match="choose another --output") as refused:
        with lifecycle(scope).hold():
            pytest.fail("A fresh start must not erase a report or foreign file")
    if extra == "user-file":
        # --rebuild would keep the foreign file as well, so only --resume is offered.
        assert "(notes.txt). Add --resume to continue it" in str(refused.value)
        assert "--rebuild" not in str(refused.value)
    assert preserved.read_bytes() == before
    assert (scope.output / ".assessment-work").is_dir()


def test_fresh_start_does_not_follow_a_linked_work_directory(scope, tmp_path):
    first = lifecycle(scope)
    _fail(first)
    target = tmp_path / "external"
    target.mkdir()
    (target / "keep.txt").write_text("preserve")
    shutil.rmtree(first.directory)
    first.directory.symlink_to(target)
    with pytest.raises(ExchangeError, match="non-directory or link"):
        with lifecycle(scope).hold():
            pytest.fail("A linked work directory must not be cleared")
    assert (target / "keep.txt").read_text() == "preserve"


def test_live_ordinary_lock_blocks_multi_repo_assessment(scope):
    scope.output.mkdir()
    acquire_lock._write_lock(scope.output / ".appsec-lock", os.getpid(), int(time.time()), "ordinary-run")
    with pytest.raises(ExchangeError, match="another live run"):
        with lifecycle(scope).hold():
            pytest.fail("Output already has a live owner")


def test_held_multi_repo_guard_blocks_ordinary_cli_and_concurrent_controller(scope):
    with lifecycle(scope).hold():
        result = subprocess.run(
            [sys.executable, str(acquire_lock.__file__), str(scope.output / ".appsec-lock"), "--run-id=other"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 1 and "LOCK_BLOCKED" in result.stdout
        with pytest.raises(acquire_lock.LockBusy):
            with lifecycle(scope, resume=True).hold():
                pytest.fail("Concurrent controller must not enter")


@pytest.mark.parametrize("target", [".appsec-lock", ".appsec-lock.guard"])
def test_external_links_are_rejected_without_modifying_target(scope, tmp_path, target):
    scope.output.mkdir()
    original = tmp_path / "external"
    original.write_text("preserve")
    (scope.output / target).symlink_to(original)
    with pytest.raises((ExchangeError, acquire_lock.LockBusy)):
        with lifecycle(scope).hold():
            pytest.fail("Linked lock must not confer ownership")
    assert original.read_text() == "preserve"


@pytest.mark.parametrize("target", [".appsec-lock", ".appsec-lock.guard"])
def test_hard_linked_locks_cannot_modify_an_external_file(scope, tmp_path, target):
    scope.output.mkdir()
    original = tmp_path / "external"
    original.write_text("preserve")
    os.link(original, scope.output / target)
    with pytest.raises((ExchangeError, acquire_lock.LockBusy)):
        with lifecycle(scope).hold():
            pytest.fail("Hard-linked locks must not confer ownership")
    assert original.read_text() == "preserve"


def test_symlinked_work_directory_cannot_resume(scope, tmp_path):
    with lifecycle(scope).hold() as initial:
        pass
    initial.directory.rmdir()
    initial.directory.symlink_to(tmp_path)
    with pytest.raises(ExchangeError, match="non-directory or link"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Work directory must remain private")


def test_expired_resume_does_not_restart_time_budget(scope):
    with lifecycle(scope).hold():
        pass
    state = stored(scope)
    state["expires_at"] = int(time.time()) - 1
    state["started_at"] = state["expires_at"] - 60
    (scope.output / ".assessment-state.json").write_text(json.dumps(state))
    with pytest.raises(ExchangeError, match="budget is exhausted"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Resume must not grant another timeout")


@pytest.mark.parametrize("change", ["nonfinite", "extended-deadline", "extra-field"])
def test_malformed_accounting_or_lifecycle_cannot_resume(scope, change):
    with lifecycle(scope).hold():
        pass
    state = stored(scope)
    if change == "nonfinite":
        state["accounting"]["spent_usd"] = float("nan")
    elif change == "extended-deadline":
        state["expires_at"] += 60
    else:
        state["model_selected_command"] = "ignored-command"
    (scope.output / ".assessment-state.json").write_text(json.dumps(state))
    with pytest.raises(ExchangeError):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Invalid lifecycle input must not reach a host")


def test_cancellation_records_interruption_and_releases_output(scope):
    with pytest.raises(HostCancelled):
        with lifecycle(scope).hold() as state:
            state.cancelled = True
            assert state.should_stop() is True
            raise HostCancelled("cancelled")
    assert stored(scope)["status"] == "interrupted"
    assert not (scope.output / ".appsec-lock").exists()


@pytest.mark.parametrize("name", ["../source.py", "/tmp/outside", ".hidden", "model\n.yaml"])
def test_untrusted_deliverable_names_cannot_select_paths(scope, name):
    with lifecycle(scope).hold() as state:
        with pytest.raises(ExchangeError, match="controller-selected basename"):
            state.complete([name])


def test_missing_deliverables_cannot_mark_complete(scope):
    with lifecycle(scope).hold() as state:
        with pytest.raises(ExchangeError, match="gated deliverables"):
            state.complete([])
        assert state.state["status"] == "running"


def test_output_ancestor_link_is_rejected(scope, tmp_path):
    link = tmp_path / "output-link"
    link.symlink_to(tmp_path, target_is_directory=True)
    untrusted = AssessmentScope(scope.repositories, link / "report")
    with pytest.raises(ExchangeError, match="non-directory or link"):
        with lifecycle(untrusted).hold():
            pytest.fail("Linked output ancestry must not be admitted")


def _accept_job(scope, selector="one", usd=0.01):
    """Run one accepted job and return its receipt path."""

    class Host:
        def invoke(self, *args):
            return HostReply({"action": "complete", "reads": [], "artifact": {"ok": True}}, usd)

    with lifecycle(scope).hold() as state:
        jobs = AssessmentJobs(
            scope,
            state.directory / "jobs",
            state.budget,
            lambda role, ceiling: Host(),
            state.should_stop,
            state.checkpoint,
        )
        jobs.execute(
            role="recon_scanner",
            selector=selector,
            instructions="trusted",
            context={},
            schema={"type": "object"},
            allowed_sources=frozenset(),
            validate=lambda a, r: None,
        )
    (receipt,) = (state.directory / "jobs").glob("*.receipt.json")
    return receipt


def _rewrite_accounting(scope, calls, spent):
    state = stored(scope)
    state["accounting"].update(calls=calls, spent_usd=spent)
    (scope.output / ".assessment-state.json").write_text(json.dumps(state))


@pytest.mark.parametrize(("selector", "calls", "spent"), [("one", 0, 0.0), ("one", 1, 0.0), ("renamed", 0, 0.02)])
def test_resume_rejects_accounting_below_accepted_receipts(scope, selector, calls, spent):
    _accept_job(scope, selector, usd=0.02)
    _rewrite_accounting(scope, calls, spent)
    with pytest.raises(ExchangeError, match="below its accepted job receipts"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Lowered accounting must not refund accepted calls")


@pytest.mark.parametrize("change", ["unreadable", "foreign-scope", "renamed-job", "link"])
def test_resume_rejects_unreadable_or_foreign_receipts(scope, tmp_path, change):
    receipt = _accept_job(scope)
    document = json.loads(receipt.read_text())
    if change == "unreadable":
        receipt.write_text("{not json")
    elif change == "foreign-scope":
        document["scope_sha256"] = "0" * 64
        receipt.write_text(json.dumps(document))
    elif change == "renamed-job":
        receipt.rename(receipt.with_name("job-" + "f" * 24 + ".receipt.json"))
    else:
        outside = tmp_path / "outside.json"
        outside.write_text(json.dumps(document))
        receipt.unlink()
        receipt.symlink_to(outside)
    with pytest.raises(ExchangeError):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Unverifiable receipts must not resume")


def test_resume_accepts_accounting_that_retains_extra_reservations(scope):
    _accept_job(scope, usd=0.01)
    # A failed call's reservation stays in state without a receipt.
    _rewrite_accounting(scope, 3, 0.11)
    with lifecycle(scope, resume=True).hold() as resumed:
        assert resumed.budget.calls == 3 and resumed.budget.spent_usd == pytest.approx(0.11)


def _completed(scope, **changes):
    with lifecycle(scope, **changes).hold() as state:
        (scope.output / "threat-model.md").write_text("report\n")
        state.complete(["threat-model.md"])


@pytest.mark.parametrize("changes", [{}, {"runtime_sha256": "b" * 64}, {"configuration": {"stride_model": "sonnet"}}])
def test_a_new_scan_replaces_a_completed_run_and_carries_its_changelog(scope, changes):
    """REQ-017: a new scan needs no --rebuild and continues the replaced run's history."""
    with lifecycle(scope).hold() as state:
        (scope.output / "threat-model.yaml").write_text("changelog:\n- date: '2026-10-17'\n")
        state.complete(["threat-model.yaml"])
    with lifecycle(scope, **changes).hold() as fresh:
        assert fresh.state["status"] == "running"
        assert set(fresh.state["superseded"]) == {"threat-model.yaml"}
        assert json.loads(fresh.history_path.read_text()) == [{"date": "2026-10-17"}]


def test_rebuild_replaces_only_an_earlier_run_that_owns_every_file(scope):
    _completed(scope)
    with lifecycle(scope, runtime_sha256="b" * 64, replace=True).hold() as fresh:
        assert fresh.state["status"] == "running"
        assert set(fresh.state["superseded"]) == {"threat-model.md"}
        assert not (fresh.directory / "jobs").exists()
        assert fresh.history_path is None


@pytest.mark.parametrize("replace", [False, True])
def test_the_earlier_report_stays_until_a_new_run_completes(scope, replace):
    _completed(scope)
    with pytest.raises(RuntimeError):
        with lifecycle(scope, replace=replace).hold():
            raise RuntimeError("new scan fails")
    assert (scope.output / "threat-model.md").read_text() == "report\n"
    # The next attempt keeps it as well, and its completion removes what it did not overwrite.
    with lifecycle(scope, replace=replace).hold() as state:
        assert (scope.output / "threat-model.md").read_text() == "report\n"
        (scope.output / "threat-model.yaml").write_text("new: model\n")
        state.complete(["threat-model.yaml"])
    assert not (scope.output / "threat-model.md").exists()
    assert "superseded" not in stored(scope)


@pytest.mark.parametrize("replace", [True, False])
@pytest.mark.parametrize("extra", ["edited-report", "user-file"])
def test_rebuild_keeps_a_directory_with_edited_or_foreign_files(scope, extra, replace):
    _completed(scope)
    kept = scope.output / ("threat-model.md" if extra == "edited-report" else "notes.txt")
    kept.write_text("mine\n")
    with pytest.raises(ExchangeError, match=rf"did not write or that changed since \({kept.name}\)"):
        with lifecycle(scope, replace=replace).hold():
            pytest.fail("A new scan must not erase a user's file")
    assert kept.read_text() == "mine\n" and (scope.output / ".assessment-state.json").exists()


def _published_then_stopped(scope, text="new report\n"):
    """A run whose publication moved its report into place but stopped before `complete`."""
    with pytest.raises(RuntimeError):
        with lifecycle(scope).hold() as state:
            state.publishing({"threat-model.md": hashlib.sha256(text.encode()).hexdigest()})
            (scope.output / "threat-model.md").write_text(text)
            raise RuntimeError("stopped before complete")


@pytest.mark.parametrize("replace", [False, True])
def test_a_fresh_start_removes_what_an_unfinished_publication_moved_into_place(scope, replace):
    _published_then_stopped(scope)
    assert "publishing" in stored(scope) and stored(scope)["status"] == "failed"
    with lifecycle(scope, replace=replace).hold() as fresh:
        # The unfinished report never stands beside the new run as if complete.
        assert not (scope.output / "threat-model.md").exists()
        assert "publishing" not in fresh.state


def test_an_edited_unfinished_publication_is_kept_and_named(scope):
    _published_then_stopped(scope)
    (scope.output / "threat-model.md").write_text("mine\n")
    for replace in (False, True):
        with pytest.raises(ExchangeError, match=r"\(threat-model\.md\)") as refused:
            with lifecycle(scope, replace=replace).hold():
                pytest.fail("A new scan must not erase an edited report")
        assert "--rebuild" not in str(refused.value)
        assert (scope.output / "threat-model.md").read_text() == "mine\n"


def test_an_edited_unfinished_publication_in_a_sole_checkout_stays_in_place(scope, tmp_path):
    reports = tmp_path / "frontend" / "docs" / "security"
    reports.mkdir(parents=True)
    sole = admit([str(tmp_path / "frontend")], str(reports), minimum=1)
    assert sole.output_in_checkout()
    _published_then_stopped(sole)
    (reports / "threat-model.md").write_text("mine\n")
    # MR-6: an edited deliverable is kept until publication overwrites it.
    with lifecycle(sole).hold() as fresh:
        assert fresh.state["status"] == "running"
    assert (reports / "threat-model.md").read_text() == "mine\n"


def test_resume_without_an_assessment_says_so(scope):
    with pytest.raises(ExchangeError, match="holds no assessment to resume; run without --resume"):
        with lifecycle(scope, resume=True).hold():
            pytest.fail("Nothing to resume")
    assert not (scope.output / ".assessment-state.json").exists()


def _restart_choice(scope, answers, budget=None):
    from types import SimpleNamespace

    from orchestrator.orchestration_controller import _assessment_restart_choice

    replies, shown = iter(answers), []
    choice = _assessment_restart_choice(
        SimpleNamespace(output=str(scope.output)),
        budget or AssessmentBudget(1.0, 0.05, 10, 60),
        readline=lambda: next(replies, ""),  # "" is end of input
        write=shown.append,
    )
    return choice, "".join(shown)


@pytest.mark.parametrize(
    ("answers", "expected"),
    [(["1\n"], "resume"), (["3\n"], "rebuild"), (["\n"], None), ([], None), (["x\n", "9\n", "4\n", "3\n"], None)],
)
def test_an_unfinished_run_asks_and_only_an_explicit_answer_resumes_or_rebuilds(scope, answers, expected):
    with lifecycle(scope).hold():
        pass
    choice, shown = _restart_choice(scope, answers)
    assert choice == expected
    assert f"An unfinished assessment is stored in {scope.output}" in shown
    assert "Interrupted, started" in shown and "Spent so far: USD 0.00." in shown
    assert "1  Continue it (--resume)" in shown and "3  Start from scratch (--rebuild)" in shown


def test_the_question_omits_a_resume_that_cannot_succeed(scope):
    with lifecycle(scope).hold():
        pass
    choice, shown = _restart_choice(scope, ["1\n", "1\n", "1\n"], budget=AssessmentBudget(2.0, 0.05, 10, 60))
    assert choice is None
    assert "1  Continue it: not available, the budget or time limits differ" in shown
    assert "--resume)" not in shown and "Choose 2 or 3 [2]:" in shown


def test_no_question_without_an_unfinished_run(scope):
    assert _restart_choice(scope, ["3\n"]) == (None, "")
    _completed(scope)
    assert _restart_choice(scope, ["3\n"]) == (None, "")


def test_held_lock_heartbeats_on_its_own_clock(scope, monkeypatch):
    monkeypatch.setattr(AssessmentState, "HEARTBEAT_SECONDS", 0.05)
    state = lifecycle(scope)
    with state.hold():
        assert acquire_lock._read_stale_after(state.lock) == AssessmentState.STALE_AFTER_SECONDS
        acquire_lock._write_lock(state.lock, os.getpid(), 1, state.state["run_id"])
        deadline = time.monotonic() + 5
        while acquire_lock._parse_lock(state.lock)[1] == 1 and time.monotonic() < deadline:
            time.sleep(0.05)
        assert acquire_lock._parse_lock(state.lock)[1] > 1
        assert acquire_lock._read_stale_after(state.lock) == AssessmentState.STALE_AFTER_SECONDS
    assert not state.lock.exists()


@pytest.mark.parametrize("request_kind", ["this-run", "other-run", "link"])
def test_a_stop_request_reaches_the_run_at_its_next_checkpoint(scope, tmp_path, request_kind):
    """`assess-stop` cannot signal a run in another PID namespace; the run reads its request instead."""
    state = lifecycle(scope)
    stop = scope.output / STOP_NAME
    with pytest.raises(HostCancelled), state.hold():
        run_id = state.state["run_id"]
        if request_kind == "this-run":
            stop.write_text(run_id + "\n")
        elif request_kind == "other-run":
            stop.write_text("assessment-other\n")
        else:
            (tmp_path / "elsewhere").write_text(run_id + "\n")
            stop.symlink_to(tmp_path / "elsewhere")
        state.checkpoint()
        # Only a request naming this run, in a regular file, stops it.
        assert state.cancelled is (request_kind == "this-run")
        raise HostCancelled("stopped")
    # A consumed request never stops the next run; another run's request is not this run's to remove.
    assert {"this-run": not stop.exists(), "other-run": stop.is_file(), "link": stop.is_symlink()}[request_kind]


def test_subscription_state_resume_and_monetary_tampering(scope):
    def subscription_state(**kwargs):
        return lifecycle(
            scope,
            configuration={
                "operator_profile": {
                    "schema_version": 1,
                    "definition_sha256": "a" * 64,
                    "models": {},
                    "adapter": "codex-cli",
                }
            },
            budget=AssessmentBudget(None, None, 10, 60, spent_usd=None, subscription=True),
            **kwargs,
        )

    state = subscription_state()
    with state.hold():
        state.budget.calls = 2
        state.checkpoint()
        document = stored(scope)
        assert document["schema_version"] == 2
        assert document["accounting"]["spent_usd"] is None
        assert document["identity"]["limits"]["max_usd"] is None
        with pytest.raises(ExchangeError, match="increase"):
            state.approve_budget_increase(50)
    resumed = subscription_state(resume=True)
    with resumed.hold():
        assert resumed.budget.calls == 2 and resumed.budget.spent_usd is None
    document = stored(scope)
    document["accounting"]["spent_usd"] = 0
    (scope.output / ".assessment-state.json").write_text(json.dumps(document))
    with pytest.raises(ExchangeError, match="contract"), subscription_state(resume=True).hold():
        pass
