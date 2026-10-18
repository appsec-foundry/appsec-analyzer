"""Application modules work independently of the command parser."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from appsec_analyzer.assessment.request import AssessmentOptions
from appsec_analyzer.score.calculation import ScoringPolicy, compute
from appsec_analyzer.score.events import ScoreEvent
from appsec_analyzer.score.progress import ScoreProgress
from tests.test_analyst_controller import Fake, response, review
from tests.test_analyst_controller import repo as _repo_fixture

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def repo(tmp_path):
    return _repo_fixture.__wrapped__(tmp_path)


@pytest.fixture
def state_root(tmp_path):
    return tmp_path / "state"


def test_feature_imports_do_not_require_or_import_the_public_cli(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "\n".join(
                [
                    "import sys",
                    "import appsec_analyzer.score.service",
                    "import appsec_analyzer.analyze_threats.cli",
                    "import appsec_analyzer.assessment.console",
                    "import appsec_analyzer.authnz_review",
                    "assert 'appsec_analyzer.cli' not in sys.modules",
                    "assert 'orchestrator.orchestration_controller' not in sys.modules",
                ]
            ),
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0, result.stderr


def test_direct_context_validation_works_outside_the_checkout(tmp_path):
    env = dict(os.environ)
    env.pop("PYTHONPATH", None)
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts/contexts/context_routing.py"), "validate"],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "schema- and semantic-valid" in result.stdout


def test_calculation_with_loaded_policy_needs_no_files_or_processes(monkeypatch):
    policy = ScoringPolicy(
        (("access", "Access control"),),
        {name: {} for name in ("config_checks", "iac_types", "cwes", "weakness_classes", "scanners")},
        "access",
        {},
        {},
        "a" * 64,
    )
    monkeypatch.setattr(Path, "read_bytes", lambda *a: pytest.fail("calculation read a file"))
    monkeypatch.setattr(Path, "read_text", lambda *a, **kw: pytest.fail("calculation read a catalog"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **kw: pytest.fail("calculation ran a process"))
    rules = [{"rule_id": f"rule-{i}", "status": "present"} for i in range(5)]
    result = compute(rules, [], policy=policy)
    assert result["score"] == 100 and result["verdict"] == "scored"
    assert result["comparability"]["catalog_fingerprint"] == "a" * 64


def test_structured_progress_keeps_scanner_failure_visible():
    stream = io.StringIO()
    with ScoreProgress(stream, style=lambda text, *roles: text) as progress:
        progress(ScoreEvent("scanner", scanner="source-auth"))
        progress(ScoreEvent("scanner", scanner="source-auth", status="failed"))
        progress(ScoreEvent("calculate"))
        progress.finish("incomplete")
    text = stream.getvalue()
    assert "[failed]" in text and "Scanning source code" in text and "Incomplete scan" in text


@pytest.mark.parametrize("options", [{"trust_mode": "unknown"}, {"width": 20}, {"max_parallel": 0}])
def test_structured_assessment_rejects_invalid_boundary_options(options):
    with pytest.raises(ValueError):
        AssessmentOptions(("/selected/repository",), **options)


def waiting(repo, state_root):
    from orchestrator import analyst_controller as ctl

    question = {"asks": "Who may export?", "why": "Defines the boundary", "affects": "export", "required": True}
    fake = Fake(lambda prompt: response(prompt, questions=[question]))
    outcome = ctl.run(review(repo, state_root), fake)
    assert outcome.state == "awaiting_answers"
    return ctl, outcome


def test_waiting_job_returns_frozen_presentation_data_without_a_model_call(repo, state_root):
    ctl, outcome = waiting(repo, state_root)
    view = ctl.waiting_job(outcome.job_id, repo, state_root)
    assert view.mode == "review" and view.scope == {"kind": "worktree"}
    assert view.outcome.questions == outcome.questions
    assert view.outcome.state == "awaiting_answers"


def test_waiting_job_cannot_read_another_repository_or_a_live_controller(repo, state_root, tmp_path):
    from runtime import analyst_state as st

    ctl, outcome = waiting(repo, state_root)
    with pytest.raises(st.AnalystStateError):
        ctl.waiting_job(outcome.job_id, tmp_path, state_root)
    root = st.job_path(outcome.job_id, repo, state_root)
    job = st.acquire(root)
    try:
        with pytest.raises(st.AnalystStateError):
            ctl.waiting_job(outcome.job_id, repo, state_root)
    finally:
        st.release(job)


def test_waiting_job_rejects_forged_repository_identity_and_releases_lock(repo, state_root):
    from runtime import analyst_state as st

    ctl, outcome = waiting(repo, state_root)
    root = st.job_path(outcome.job_id, repo, state_root)
    request = st.read_artifact(root, "request.json")
    request["repository"]["root"] = str(repo.parent)
    (root / "request.json").write_text(json.dumps(request))
    with pytest.raises(ValueError, match="selected repository"):
        ctl.waiting_job(outcome.job_id, repo, state_root)
    job = st.acquire(root)
    st.release(job)


def test_assessment_identity_includes_application_implementation(tmp_path, monkeypatch):
    from orchestrator import orchestration_controller as ctl

    from appsec_analyzer import engine

    module = tmp_path / "service.py"
    module.write_text("VERSION = 1\n")
    monkeypatch.setattr(engine, "implementation_files", lambda: iter([("appsec_analyzer/score/service.py", module)]))
    before = ctl._assessment_runtime_fingerprint()
    module.write_text("VERSION = 2\n")
    assert ctl._assessment_runtime_fingerprint() != before


def test_application_identity_rejects_links(tmp_path, monkeypatch):
    from appsec_analyzer import engine

    package = tmp_path / "appsec_analyzer"
    package.mkdir()
    (package / "engine.py").write_text("")
    outside = tmp_path / "outside"
    outside.mkdir()
    (package / "score").symlink_to(outside, target_is_directory=True)
    monkeypatch.setattr(engine, "__file__", str(package / "engine.py"))
    with pytest.raises(RuntimeError, match="directory links"):
        list(engine.implementation_files())


@pytest.mark.parametrize("body", ['{"questions": [null]}', '{"questions": []}', "invalid json"])
def test_waiting_job_rejects_malformed_or_missing_pending_questions(repo, state_root, body):
    from runtime import analyst_state as st

    ctl, outcome = waiting(repo, state_root)
    root = st.job_path(outcome.job_id, repo, state_root)
    (root / "questions.json").write_text(body)
    with pytest.raises(ValueError, match="checkpoint"):
        ctl.waiting_job(outcome.job_id, repo, state_root)
    job = st.acquire(root)
    st.release(job)
