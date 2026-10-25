"""Startup scope reflects admitted, enabled case sources without claiming verification."""

import json
from types import SimpleNamespace

import pytest
import yaml
from orchestrator import orchestration_controller as controller
from orchestrator.assessment_review import AssessmentReviewError
from runtime.multi_repo_scope import admit

from appsec_analyzer.assessment.scope import scope_facts
from tests.test_multi_repo_controller import checkout


def _cases(*ids):
    return yaml.safe_dump(
        {
            "schema_version": 2,
            "abuse_cases": [
                {"id": cid, "kind": "descriptive", "title": "Private business rule", "check": "Check repeated refunds."}
                for cid in ids
            ],
        }
    )


def _scope(tmp_path, files=None, names=("app",)):
    for name in names:
        root = tmp_path / name
        checkout(root)
        for path, text in (files or {}).items():
            target = root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
    return admit([str(tmp_path / name) for name in names], str(tmp_path / "results"), minimum=1)


def test_scope_describes_model_backed_analysis_and_loaded_defaults(tmp_path):
    scope = _scope(tmp_path)
    rows = dict(scope_facts(scope, {"assessment_depth": "quick"}))
    assert rows == {
        "Focus": "Security design, code, and configuration",
        "Abuse cases": "Built-in",
        "Coverage": "Depends on models, context, depth, and budget",
        "Excludes": "SCA/CVE scanning, comprehensive secret scanning, and runtime testing",
    }
    # Thorough may derive cases later; startup never claims to have them.
    assert scope_facts(scope, {"assessment_depth": "thorough"}) == list(rows.items())


def test_scope_counts_enabled_cases_and_deduplicates_explicit_repository_files(tmp_path):
    path = "docs/security/abuse-cases/custom.yaml"
    scope = _scope(tmp_path, {path: _cases("REPO-AC-901", "REPO-AC-902")})
    team = tmp_path / "team"
    (team / "abuse-cases").mkdir(parents=True)
    (team / "abuse-cases" / "cases.yaml").write_text(_cases("ORG-AC-901"))
    profile = team / "profile.yaml"
    profile.write_text(yaml.safe_dump({"abuse_cases": {"inherit_defaults": False, "disable": ["REPO-AC-902"]}}))
    cfg = {"org_profile_path": str(profile), "abuse_case_files": [path, path]}
    assert dict(scope_facts(scope, cfg))["Abuse cases"] == f"organization + 1 user-supplied ({path})"
    assert dict(scope_facts(scope, {**cfg, "only_abuse_case_ids": ["ORG-AC-901"]}))["Abuse cases"] == "organization"


@pytest.mark.parametrize("explicit, count", [(["review/one.yaml"], 2), (["review/one.yaml", "review/two.yaml"], 4)])
def test_scope_counts_automatic_repository_cases_and_multiple_explicit_sources(tmp_path, explicit, count):
    scope = _scope(
        tmp_path,
        {
            ".appsec/abuse-cases/auto.yaml": _cases("REPO-AC-900"),
            "review/one.yaml": _cases("REPO-AC-901"),
            "review/two.yaml": _cases("REPO-AC-902", "REPO-AC-903"),
        },
    )
    cfg = {"abuse_case_files": explicit}
    assert dict(scope_facts(scope, cfg))["Abuse cases"] == f"Built-in + {count} user-supplied"


def test_resolved_organization_settings_reach_startup_and_downstream_case_consumers(tmp_path):
    from model.derive_abuse_cases import _active_cases
    from orchestrator.assessment_review import persist_abuse_cases

    scope = _scope(tmp_path)
    profile = tmp_path / "org-profile.yaml"
    (tmp_path / "abuse-cases").mkdir()
    (tmp_path / "abuse-cases" / "org.yaml").write_text(_cases("ORG-AC-901"))
    profile.write_text(
        "api_version: appsec-advisor.org-profile/v2\n"
        "organization: {id: testco, name: TestCo, profile_version: t1}\n"
        'compatibility: {core: ">=0.0 <999.0"}\n'
        "abuse_cases: {inherit_defaults: false}\n"
        "default_preset: std\npresets:\n  std:\n    base_mode: standard\n"
    )
    budget = controller._assessment_budget(
        controller._assessment_argument_parser().parse_args(["--repo", str(tmp_path / "app"), "--hard-budget", "5"])
    )

    def no_model(*args):
        pytest.fail("scope resolution must not call a model")

    with controller._assessment_session(
        scope, ["--org-profile", str(profile)], budget=budget, host_factory=no_model
    ) as (cfg, _state, _jobs):
        assert cfg["org_profile"]["active"] and cfg["org_profile_path"] == str(profile)
        assert dict(scope_facts(scope, cfg))["Abuse cases"] == "organization"
        assert [case["id"] for case in _active_cases(tmp_path, cfg)] == ["ORG-AC-901"]
        commands = []
        persist_abuse_cases(tmp_path, tmp_path / "app", cfg, lambda script, args: commands.append(args))
        assert commands[0][-2:] == ["--org-profile", str(profile)]


def test_scope_reads_the_frozen_source_and_sanitizes_its_display_name(tmp_path):
    path = "review/\x9bcases\x85.yaml"
    scope = _scope(tmp_path, {path: _cases("REPO-AC-901")})
    # Replacing live source cannot influence the header's admitted case count.
    (tmp_path / "app" / path).write_text(_cases("REPO-AC-901", "REPO-AC-902"))
    text = dict(scope_facts(scope, {"abuse_case_files": [path]}))["Abuse cases"]
    assert text == "Built-in + 1 user-supplied (review/ cases .yaml)"
    assert "Private business rule" not in text
    assert "\x9b" not in text and "\x85" not in text


def test_disabled_verification_does_not_read_any_case_source():
    rows = dict(scope_facts(None, {"skip_abuse_case_verification": True, "abuse_case_files": ["missing.yaml"]}))
    assert rows["Abuse cases"] == "Dedicated verification disabled"


def test_scope_does_not_claim_builtins_when_the_profile_disables_them(tmp_path):
    scope = _scope(tmp_path)
    profile = tmp_path / "profile.yaml"
    profile.write_text("abuse_cases:\n  inherit_defaults: false\n")
    assert dict(scope_facts(scope, {"org_profile_path": str(profile)}))["Abuse cases"] == "None loaded"


@pytest.mark.parametrize("cfg", [{"abuse_case_files": ["../outside.yaml"]}, {"only_abuse_case_ids": ["UNKNOWN"]}])
def test_invalid_case_selection_is_refused(tmp_path, cfg):
    scope = _scope(tmp_path)
    with pytest.raises(AssessmentReviewError):
        scope_facts(scope, cfg)


def test_invalid_explicit_content_fails_without_echoing_it(tmp_path):
    scope = _scope(tmp_path, {"review/cases.yaml": "schema_version: PRIVATE-INVALID\nabuse_cases: []\n"})
    with pytest.raises(AssessmentReviewError, match="sources are invalid") as caught:
        scope_facts(scope, {"abuse_case_files": ["review/cases.yaml"]})
    assert "PRIVATE-INVALID" not in str(caught.value) and str(tmp_path) not in str(caught.value)


def test_rejected_repository_file_does_not_count_as_user_supplied(tmp_path):
    scope = _scope(tmp_path, {".appsec/abuse-cases/bad.yaml": "schema_version: invalid\n"})
    assert dict(scope_facts(scope, {}))["Abuse cases"] == "Built-in; 1 case file(s) rejected"


def test_multiple_repositories_resolve_shared_sources_without_per_repo_cases(tmp_path):
    scope = _scope(tmp_path, names=("frontend", "backend"))
    assert dict(scope_facts(scope, {}))["Abuse cases"] == "Built-in"
    with pytest.raises(AssessmentReviewError, match="multi-repository"):
        scope_facts(scope, {"abuse_case_files": ["review/cases.yaml"]})


def test_scope_facts_reach_console_and_structured_start_without_stdout(tmp_path, capsys):
    scope = _scope(tmp_path, {"review/cases.yaml": _cases("REPO-AC-901")})
    cfg = {"abuse_case_files": ["review/cases.yaml"]}
    facts = scope_facts(scope, cfg)
    ns = controller._assessment_argument_parser().parse_args(
        ["--repo", str(tmp_path / "app"), "--output", str(tmp_path / "results"), "--hard-budget", "5"]
    )
    budget = controller._assessment_budget(ns)
    rows = controller._assessment_intro(ns, budget, "standard", "Models: m1", "P", cfg=cfg, scope_facts=facts)
    console = controller._AssessmentConsole(verbose=False)
    console.facts(None, rows)
    captured = capsys.readouterr()
    assert captured.out == ""
    for key, value in facts:
        assert dict(rows)[key] == value
        assert value in captured.err
    # The follower receives the same resolved scope as the terminal header.
    lines = controller._assessment_start_lines(
        ns, budget, "standard", cfg, SimpleNamespace(resume=False, reused_run_started=None), facts
    )
    feed = tmp_path / "progress.jsonl"
    controller._AssessmentProgress.open(str(feed))
    try:
        controller._AssessmentProgress.emit("run_start", lines=lines)
    finally:
        controller._AssessmentProgress.end(0)
    start = json.loads(feed.read_text().splitlines()[0])
    assert all(f"{key:<11} {value}" in start["lines"] for key, value in facts)


@pytest.mark.parametrize("mode", ["console", "quiet", "callback"])
def test_startup_reports_scope_before_model_work_and_quiet_preserves_the_start_event(
    tmp_path, monkeypatch, capsys, mode
):
    _scope(tmp_path, {"review/cases.yaml": _cases("REPO-AC-901")})
    feed = tmp_path / "progress.jsonl"
    messages = []

    class HeaderObserved(Exception):
        pass

    def stop_before_model(*args, **kwargs):
        raise HeaderObserved

    def no_model(*args):
        pytest.fail("startup must report scope before any model call")

    monkeypatch.setattr(controller, "_assessment_architecture", stop_before_model)
    args = [
        "--repo",
        str(tmp_path / "app"),
        "--output",
        str(tmp_path / "results"),
        "--hard-budget",
        "5",
        "--progress-file",
        str(feed),
        "--abuse-case-file",
        "review/cases.yaml",
    ]
    if mode == "quiet":
        args.append("--quiet")
    try:
        with pytest.raises(HeaderObserved):
            controller.assess_repositories(
                args, host_factory=no_model, progress=messages.append if mode == "callback" else None
            )
    finally:
        controller._AssessmentConsole.stop()
        controller._AssessmentProgress.end(1)
    captured = capsys.readouterr()
    assert captured.out == ""
    expected = "Built-in + 1 user-supplied (review/cases.yaml)"
    start = next(row for line in feed.read_text().splitlines() if (row := json.loads(line))["event"] == "run_start")
    assert f"{'Abuse cases':<11} {expected}" in start["lines"]
    assert (expected in captured.err) is (mode == "console")
    assert (f"Abuse cases: {expected}" in messages) is (mode == "callback")
    for section in ("  Run\n", "  Scope\n", "  Workflow & results\n"):
        assert (section in captured.err) is (mode == "console")
    if mode == "console":
        assert "USD 5.00" in captured.err
        assert "required analysis and report take priority" not in captured.err


def _org_profile(tmp_path, required):
    profile = tmp_path / "org-profile.yaml"
    profile.write_text(
        "api_version: appsec-advisor.org-profile/v2\n"
        "organization: {id: testco, name: TestCo, profile_version: t1}\n"
        'compatibility: {core: ">=0.0 <999.0"}\n'
        f"test_cases: {{required: {json.dumps(required)}}}\n"
        "default_preset: std\npresets:\n  std:\n    base_mode: standard\n"
    )
    return profile


def _session(scope, tmp_path, test_cases, required):
    budget = controller._assessment_budget(
        controller._assessment_argument_parser().parse_args(["--repo", str(tmp_path / "app"), "--hard-budget", "5"])
    )

    def no_model(*args):
        pytest.fail("a refused run must not reach a model")

    profile = _org_profile(tmp_path, required)
    return controller._assessment_session(
        scope, ["--org-profile", str(profile)], budget=budget, host_factory=no_model, test_cases=test_cases
    )


def test_a_required_test_case_reaches_the_session_configuration(tmp_path):
    scope = _scope(tmp_path)
    config = {"aspects": ["IAM"], "disable": [{"id": "TC-CI-01", "reason": "legacy pipeline"}]}
    with _session(scope, tmp_path, config, ["TC-INFRA-01"]) as (cfg, _state, _jobs):
        assert cfg["org_profile_test_cases_required"] == ["TC-INFRA-01"]
        assert cfg["test_cases"] == config


def test_disabling_a_required_test_case_is_refused_before_the_run_state_exists(tmp_path):
    scope = _scope(tmp_path)
    config = {"aspects": [], "disable": [{"id": "TC-CI-01", "reason": "legacy pipeline"}]}
    with pytest.raises(controller.CallError, match="TC-CI-01 is required by the organization profile"):
        with _session(scope, tmp_path, config, ["TC-CI-01", "TC-INFRA-01"]):
            pytest.fail("the session must not start")
    assert not (scope.output / ".assessment-state.json").exists()


@pytest.mark.parametrize("test_cases", [False, True, {"aspects": [], "disable": []}])
def test_a_run_that_disables_nothing_is_not_refused(tmp_path, test_cases):
    scope = _scope(tmp_path)
    with _session(scope, tmp_path, test_cases, ["TC-CI-01"]) as (cfg, _state, _jobs):
        assert bool(cfg["test_cases"]) is bool(test_cases)


def test_the_method_rows_explain_each_method_and_put_the_verified_aspects_under_verify():
    methods = controller._AssessmentConsole.METHODS
    survey = ("Survey", methods["Survey"])
    # Without verification the scanners' hits are starting points for the survey alone, and no Verify row follows.
    assert controller._method_rows(None) == [
        ("Scanners", methods["Scanners"].format(starts="the survey")),
        survey,
    ]
    rows = controller._method_rows({"aspects": ["AuthZ", "DataProt"]})
    assert rows[0] == ("Scanners", methods["Scanners"].format(starts="survey and verify"))
    assert rows[1:] == [survey, ("Verify", f"{methods['Verify']} · AuthZ, DataProt")]
    assert controller._method_rows({"aspects": []})[-1] == ("Verify", f"{methods['Verify']} · scanner rules only")
