"""Fast report resume preserves admission, accounting and artifact integrity."""

import json
import os
import shutil
import stat

import pytest
from orchestrator import assessment_checkpoint as checkpoint
from orchestrator import orchestration_controller as controller
from runtime.analyst_host import HostCancelled, HostReply
from runtime.assessment_host import ExchangeError
from runtime.assessment_jobs import AssessmentBudget

from tests.test_assessment_state import _accept_job, _plugin_change_jobs, lifecycle
from tests.test_assessment_state import scope as _scope_fixture
from tests.test_multi_repo_assessment import FullHost, _assess

scope = _scope_fixture


@pytest.fixture
def prepared(scope):
    _accept_job(scope)
    with lifecycle(scope, resume=True).hold() as state:
        jobs = _plugin_change_jobs(state, lambda *args: pytest.fail("snapshot reuse must not call a model"))
        workspace = state.directory / "render"
        workspace.mkdir()
        (workspace / ".fragments").mkdir()
        (workspace / ".fragments/security-architecture.md").write_text("Accepted architecture")
        (workspace / "threat-model.yaml").write_text("threats: []\n")
        jobs.infos.append({"component": "api", "files": ["unchecked.py"]})
        jobs.notes.append("Earlier coverage note")
        checkpoint.save(state, jobs, workspace, {"marker": "accepted"})
    folder = state.directory / ("render-checkpoint-" + state.state["render_checkpoint"])
    return state, workspace, folder


def test_resume_restores_accepted_report_and_coverage_without_recharging(prepared, scope):
    previous, workspace, _ = prepared
    (workspace / "threat-model.yaml").write_text("Partially written after the stop")
    with lifecycle(scope, resume=True).hold() as state:
        jobs = _plugin_change_jobs(state, lambda *args: pytest.fail("unexpected model call"))
        assert checkpoint.restore(state, jobs, workspace) == {"marker": "accepted"}
        assert (workspace / "threat-model.yaml").read_text() == "threats: []\n"
        assert jobs.infos == [{"component": "api", "files": ["unchecked.py"]}]
        assert jobs.notes == ["Earlier coverage note"]
        assert jobs.job_counts() == (1, 0)
        assert jobs.budget.calls == previous.budget.calls == 1
        assert jobs.budget.spent_usd == previous.budget.spent_usd == pytest.approx(0.01)
        assert stat.S_IMODE((workspace / "threat-model.yaml").stat().st_mode) == 0o600


def test_subscription_resume_preserves_call_count_and_unavailable_monetary_cost(scope):
    configuration = {
        "operator_profile": {
            "schema_version": 1,
            "definition_sha256": "d" * 64,
            "models": {},
            "adapter": "codex-cli",
        }
    }

    def session(resume=False):
        return lifecycle(
            scope,
            resume=resume,
            configuration=configuration,
            budget=AssessmentBudget(None, None, 10, 60, spent_usd=None, subscription=True),
        )

    class Host:
        def invoke(self, *args):
            return HostReply({"action": "complete", "reads": [], "artifact": {"ok": True}}, None)

    with session().hold() as state:
        jobs = _plugin_change_jobs(state, lambda *args: Host())
        jobs.execute(
            role="recon_scanner",
            selector="one",
            instructions="trusted",
            context={},
            schema={"type": "object"},
            allowed_sources=frozenset(),
            validate=lambda *args: None,
        )
        workspace = state.directory / "render"
        workspace.mkdir()
        (workspace / "threat-model.yaml").write_text("threats: []\n")
        assert checkpoint.save(state, jobs, workspace, {"marker": "accepted"})
    with session(resume=True).hold() as resumed:
        jobs = _plugin_change_jobs(resumed, lambda *args: pytest.fail("unexpected model call"))
        assert checkpoint.restore(resumed, jobs, workspace) == {"marker": "accepted"}
        assert jobs.budget.calls == 1 and jobs.budget.spent_usd is None
        assert jobs.job_counts() == (1, 0)


@pytest.mark.parametrize("kind", ["manifest", "fragment", "symlink", "hardlink", "job", "receipt", "directory"])
def test_changed_or_linked_snapshot_and_accepted_jobs_stop_before_reuse(prepared, scope, kind):
    previous, workspace, folder = prepared
    target = folder / "workspace/threat-model.yaml"
    if kind == "manifest":
        target = folder / "manifest.json"
    elif kind in ("job", "receipt"):
        receipt = next((previous.directory / "jobs").glob("*.receipt.json"))
        target = receipt if kind == "receipt" else receipt.with_name(receipt.name.replace(".receipt", ""))
    elif kind == "directory":
        target = folder / "workspace/.fragments"
        shutil.rmtree(target)
        target.symlink_to(workspace / ".fragments", target_is_directory=True)
    if kind == "symlink":
        target.unlink()
        target.symlink_to(workspace / "threat-model.yaml")
    elif kind == "hardlink":
        target.unlink()
        os.link(workspace / "threat-model.yaml", target)
    elif kind not in ("directory",):
        if kind == "receipt":
            receipt = json.loads(target.read_text())
            receipt["request_sha256"] = "b" * 64
            target.write_text(json.dumps(receipt))
        elif kind == "job":
            target.write_text('{"ok": false}')
        else:
            target.write_text("changed")
    with lifecycle(scope, resume=True).hold() as state:
        jobs = _plugin_change_jobs(state, lambda *args: pytest.fail("unexpected model call"))
        with pytest.raises(ExchangeError):
            checkpoint.restore(state, jobs, workspace)
        assert jobs.job_counts() == (0, 0)
        assert (workspace / "threat-model.yaml").read_text() == "threats: []\n"


@pytest.mark.parametrize("missing", ["manifest", "fragment", "snapshot", "job", "receipt"])
def test_missing_snapshot_or_dependency_falls_back_without_replacing_workspace(prepared, scope, missing):
    previous, workspace, folder = prepared
    if missing == "snapshot":
        shutil.rmtree(folder)
    else:
        target = folder / ("manifest.json" if missing == "manifest" else "workspace/threat-model.yaml")
        if missing in ("job", "receipt"):
            target = next((previous.directory / "jobs").glob("*.receipt.json"))
            if missing == "job":
                target = target.with_name(target.name.replace(".receipt", ""))
        target.unlink()
    (workspace / "threat-model.yaml").write_text("Existing mutable workspace")
    with lifecycle(scope, resume=True).hold() as state:
        jobs = _plugin_change_jobs(state, lambda *args: pytest.fail("unexpected model call"))
        assert checkpoint.restore(state, jobs, workspace) is None
        assert (workspace / "threat-model.yaml").read_text() == "Existing mutable workspace"


def test_a_runtime_change_replays_jobs_instead_of_trusting_the_snapshot(prepared, scope):
    _, workspace, _ = prepared
    with lifecycle(scope, resume=True, runtime_sha256="b" * 64).hold() as state:
        assert state.runtime_changed
        jobs = _plugin_change_jobs(state, lambda *args: pytest.fail("unexpected model call"))
        assert checkpoint.restore(state, jobs, workspace) is None


def test_changed_external_context_does_not_reuse_the_old_report(prepared, scope):
    _, workspace, _ = prepared
    with lifecycle(scope, resume=True).hold() as state:
        jobs = _plugin_change_jobs(state, lambda *args: pytest.fail("unexpected model call"))
        assert checkpoint.restore(state, jobs, workspace, inputs={"context": "changed"}) is None


@pytest.mark.parametrize("limit", ["MAX_ENTRIES", "MAX_TOTAL_BYTES", "MAX_DELIVERABLE_BYTES"])
def test_a_report_above_snapshot_limits_keeps_normal_resume(prepared, scope, monkeypatch, limit):
    _, workspace, _ = prepared
    with lifecycle(scope, resume=True).hold() as state:
        jobs = _plugin_change_jobs(state, lambda *args: pytest.fail("unexpected model call"))
        fingerprint = state.state["render_checkpoint"]
        monkeypatch.setattr(checkpoint, limit, 1)
        assert not checkpoint.save(state, jobs, workspace, {"marker": "new"})
        assert state.state["render_checkpoint"] == fingerprint


@pytest.mark.parametrize("names", [("solo",), ("caller", "receiver")])
def test_summary_resume_skips_analysis_and_preparation_but_runs_publication_gates(tmp_path, monkeypatch, names):
    coverage = {}

    def stop_at_summary(text):
        if text.startswith("Review coverage: "):
            detail = text.removeprefix("Review coverage: ")
            coverage[detail.partition(":")[0]] = detail
        if text.startswith("Stage 2: Management Summary"):
            raise HostCancelled("Stopped at the summary")

    host = FullHost()
    with pytest.raises(HostCancelled):
        _assess(tmp_path, monkeypatch, names, ("--no-pdf",), host=host, progress=stop_at_summary)
    output = tmp_path / "out"
    state = json.loads((output / ".assessment-state.json").read_text())
    assert state["render_checkpoint"] and state["status"] == "interrupted"
    assert "secarch_renderer" in host.roles and "ms_renderer" not in host.roles
    assert not (output / "appsec-assessment.yaml").exists()
    host.roles.clear()
    monkeypatch.setattr(controller, "_assessment_architecture", lambda *a, **k: pytest.fail("analysis replayed"))
    monkeypatch.setattr(controller, "_assessment_prepare_render", lambda *a, **k: pytest.fail("report rebuilt"))
    run_script = controller._run_script
    gates = []

    def tracked(script, args, **kwargs):
        gates.append((script, args))
        return run_script(script, args, **kwargs)

    monkeypatch.setattr(controller, "_run_script", tracked)
    progress = []
    arguments = [
        *[arg for name in names for arg in ("--repo", str(tmp_path / name))],
        "--output",
        str(output),
        "--hard-budget",
        "5",
        "--trust-mode",
        "trusted",
        "--model",
        "haiku",
        "--no-pdf",
        "--resume",
    ]
    if len(names) > 1:

        def stop_after_summary(text):
            if text == "Running the quality gates":
                raise HostCancelled("Stopped after accepting the summary")

        with pytest.raises(HostCancelled):
            controller.assess_repositories(arguments, host_factory=host.factory, progress=stop_after_summary)
        assert host.roles == ["ms_renderer"]
        host.roles.clear()
        gates.clear()
    outcome = controller.assess_repositories(
        arguments,
        host_factory=host.factory,
        progress=progress.append,
    )
    assert outcome["status"] == "complete"
    assert outcome["review_coverage"] == list(coverage.values())
    assert host.roles == (["ms_renderer"] if len(names) == 1 else [])
    assert any(text.startswith("Resuming at Management Summary") for text in progress)
    assert not any(text.startswith("Stage 2: Security Architecture") for text in progress)
    assert any(script == "validators/assert_completeness.py" for script, _ in gates)
    assert any(script == "validators/qa_checks.py" and args[0] == "published_secrets" for script, args in gates)
    assert outcome["calls"] == state["accounting"]["calls"] + 1
    assert outcome["spent_usd"] == pytest.approx(state["accounting"]["spent_usd"] + 0.01)
    assert (output / "appsec-assessment.md").is_file()
    assert not list((output / ".assessment-work").glob("render-checkpoint-*"))
    events = [
        json.loads(line)
        for feed in (output / ".assessment-work/diagnostics").glob("attempt-*/events.jsonl")
        for line in feed.read_text().splitlines()
    ]
    assert any(event["event"] == "render_checkpoint_reused" for event in events)
    assert any(event["event"] == "job_reused" and event.get("checkpoint") for event in events)
