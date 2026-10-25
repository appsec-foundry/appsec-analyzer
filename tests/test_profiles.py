"""Profile configuration, operator boundaries, and actual role dispatch (offline)."""

from __future__ import annotations

import json
import subprocess

import pytest
import yaml

from appsec_analyzer import cli, depth_settings, profiles, resource_root
from tests.test_public_assessment_operations import openai_metadata as openai_metadata

REASON = {"id": "TC-CI-01", "reason": "legacy pipeline"}
BAD_TEST_CASE_OBJECTS = (
    {"aspects": []},
    {"aspects": ["Infra"]},
    {"aspects": ["AuthN", "AuthN"]},
    {"aspects": "AuthN"},
    {"unknown": True},
    {"disable": [{"id": "TC-CI-01"}]},
    {"disable": [{"id": "TC-CI-01", "reason": ""}]},
    {"disable": [{"id": "TC-CI-01", "reason": "x" * 301}]},
    {"disable": [{"id": "TC-CI-01", "reason": "bad\nreason"}]},
    {"disable": [{"id": "TC-CI-01", "reason": "ok", "extra": 1}]},
    {"disable": [{"id": "tc-ci-01", "reason": "ok"}]},
    {"disable": [{"id": "TC-NOPE-99", "reason": "not in the catalog"}]},
    {"disable": [REASON, {**REASON, "reason": "again"}]},
    {"disable": REASON},
)


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    root = profiles.config_home()
    (root / "profiles").mkdir(parents=True)
    (root / "model-profiles").mkdir()
    return root


def write(home, kind, name, doc):
    path = home / ("profiles" if kind == "scan" else "model-profiles") / f"{name}.yaml"
    path.write_text(yaml.safe_dump(doc), encoding="utf-8")
    return path


def sample(home, *, model=None):
    write(
        home,
        "scan",
        "release",
        {
            "schema_version": 1,
            "model_profile": "team-sol",
            "budget": 30,
            "assessment_depth": "thorough",
            "outputs": ["markdown", "sarif"],
            "report": {"attributes": {"team": "payments"}},
        },
    )
    write(
        home,
        "model",
        "team-sol",
        model
        or {
            "schema_version": 1,
            "base": "codex",
            "defaults": {"reasoning_effort": "medium"},
            "roles": {
                "recon_scanner": {"model": "gpt-luna", "reasoning_effort": "low"},
                "stride_analyzer": {"reasoning_effort": "high"},
            },
            "depths": {"thorough": {"roles": {"stride_analyzer": {"reasoning_effort": "max"}}}},
        },
    )


def test_user_defaults_role_depth_and_cli_precedence(home):
    sample(home)
    resolved = profiles.resolve_scan("release", budget=12, outputs=["html"])
    assert resolved["settings"]["budget"] == 12
    assert resolved["settings"]["outputs"] == ["markdown", "yaml", "html"]
    assert resolved["origins"]["settings"]["budget"] == "CLI"
    assert resolved["models"]["stride_analyzer"]["reasoning_effort"] == "max"
    assert resolved["models"]["evidence_verifier"]["reasoning_effort"] == "medium"
    assert resolved["models"]["recon_scanner"]["model"] == "gpt-6-luna"
    assert resolved["models"]["recon_scanner"]["input_usd_per_million"] == 0.125
    assert all("max_output_tokens" not in row for row in resolved["models"].values())
    assert resolved["attributes"] == {"team": "payments"}


def test_max_parallel_defaults_profile_cli_and_provenance(home):
    assert profiles.resolve_scan("claude")["settings"]["max_parallel"] == 4
    write(home, "scan", "parallel", {"schema_version": 1, "max_parallel": 4})
    configured = profiles.resolve_scan("parallel")
    assert configured["settings"]["max_parallel"] == 4
    assert configured["origins"]["settings"]["max_parallel"].endswith("parallel.yaml")
    override = profiles.resolve_scan("parallel", max_parallel=1)
    assert override["settings"]["max_parallel"] == 1
    assert override["origins"]["settings"]["max_parallel"] == "CLI"
    assert configured["definition_sha256"] != override["definition_sha256"]


@pytest.mark.parametrize("command", ["assess"])
@pytest.mark.parametrize("override, expected", [(None, 4), (1, 1), (16, 16)])
def test_public_max_parallel_reaches_controller_from_profile_or_cli(
    home, tmp_path, monkeypatch, command, override, expected
):
    write(home, "scan", "parallel", {"schema_version": 1, "max_parallel": 4})
    from appsec_analyzer import hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller as controller

    seen = {}

    def assess(args, **kwargs):
        seen.update(args=args, profile=kwargs["run_profile"])
        ns, _ = controller._assessment_argument_parser().parse_known_args(args)
        assert controller._assessment_budget(ns).max_parallel == expected
        return 0

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(controller, "assess_main", assess)
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    args = [command, "--repo", str(repo), "--profile", "parallel"]
    if override is not None:
        args += ["--max-parallel", str(override)]
    assert cli.main(args) == 0
    assert seen["args"][seen["args"].index("--max-parallel") + 1] == str(expected)
    assert seen["profile"]["settings"]["max_parallel"] == expected


def test_test_cases_default_follows_the_depth(home):
    plain = profiles.resolve_scan("claude")
    assert plain["settings"]["test_cases"] == {
        "aspects": ["AuthN", "AuthZ", "InputVal", "AI"],
        "disable": [],
    }
    assert plain["origins"]["settings"]["test_cases"] == "analyzer default for standard depth"
    assert profiles.resolve_scan("claude", depth="quick")["settings"]["test_cases"] is False
    assert profiles.resolve_scan("claude", depth="thorough")["settings"]["test_cases"] == {
        "aspects": ["AuthN", "AuthNRoutes", "AuthZ", "InputVal", "DataProt", "AI"],
        "disable": [],
    }
    write(home, "scan", "cases", {"schema_version": 1, "test_cases": True})
    enabled = profiles.resolve_scan("cases")
    assert enabled["settings"]["test_cases"] is True
    assert enabled["origins"]["settings"]["test_cases"].endswith("cases.yaml")
    assert enabled["definition_sha256"] != plain["definition_sha256"]


def test_depth_values_override_single_depths_and_keep_the_others(home):
    depths = {"standard": {"verify": ["InputVal", "AuthZ"], "abuse_cases": 5}, "quick": {"verify": []}}
    write(home, "scan", "team", {"schema_version": 1, "depths": depths, "test_cases": {"disable": [REASON]}})
    standard = profiles.resolve_scan("team")["settings"]
    assert standard["test_cases"] == {"aspects": ["AuthZ", "InputVal"], "disable": [REASON]}
    assert standard["depth_settings"]["abuse_cases"] == 5
    assert profiles.resolve_scan("team", depth="quick")["settings"]["test_cases"] is False
    thorough = profiles.resolve_scan("team", depth="thorough")["settings"]
    assert thorough["test_cases"]["aspects"] == ["AuthN", "AuthNRoutes", "AuthZ", "InputVal", "DataProt", "AI"]
    assert thorough["depth_settings"] == depth_settings.shipped("thorough")
    write(
        home,
        "scan",
        "some",
        {"schema_version": 1, "depths": {"quick": {"verify": ["AI"]}}, "test_cases": {"aspects": ["DataProt"]}},
    )
    assert profiles.resolve_scan("some", depth="quick")["settings"]["test_cases"]["aspects"] == ["AI"]
    # `aspects` covers every depth whose `verify` the scan profile does not set.
    assert profiles.resolve_scan("some")["settings"]["test_cases"]["aspects"] == ["DataProt"]


def test_a_depth_budget_in_the_scan_profile_applies_unless_the_cli_sets_one(home):
    write(home, "scan", "team", {"schema_version": 1, "budget": 25, "depths": {"thorough": {"budget": 40}}})
    thorough = profiles.resolve_scan("team", depth="thorough")
    assert thorough["settings"]["budget"] == 40
    assert thorough["origins"]["settings"]["budget"].endswith("team.yaml (depths.thorough.budget)")
    # Other depths keep the profile's budget, and an explicit CLI budget wins.
    assert profiles.resolve_scan("team")["settings"]["budget"] == 25
    assert profiles.resolve_scan("team", depth="thorough", budget=12)["settings"]["budget"] == 12
    # Without the team's own value, the shipped depth budgets stay with the Claude Code dialogue.
    assert profiles.resolve_scan("claude", depth="thorough")["settings"]["budget"] == 20
    write(home, "scan", "plan", {"schema_version": 1, "model_profile": "codex-cli", "depths": {"quick": {"budget": 9}}})
    assert profiles.resolve_scan("plan", depth="quick")["settings"]["budget"] is None


def test_assess_without_a_profile_uses_the_operators_default_and_fails_closed(home, monkeypatch, capsys):
    from appsec_analyzer import hosts

    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not start"))
    repo = "https://example.invalid/repo.git"
    assert profiles.default_scan() == "claude"
    path = write(home, "scan", "default", {"schema_version": 1, "test_cases": "yes"})
    assert profiles.default_scan() == "default"
    # An invalid default stops the run instead of falling back to the Claude profile.
    assert cli.main(["assess", "--repo", repo]) == 2
    assert "invalid scan profile (test_cases." in capsys.readouterr().err
    # Automation still names its profile.
    assert cli.main(["assess", "--repo", repo, "--non-interactive"]) == 2
    assert "requires --repo and an explicit --profile" in capsys.readouterr().err
    path.unlink()
    target = home / "elsewhere.yaml"
    target.write_text(yaml.safe_dump({"schema_version": 1}), encoding="utf-8")
    path.symlink_to(target)
    assert profiles.default_scan() == "default"
    with pytest.raises(profiles.ProfileError):
        profiles.resolve_scan("default")


@pytest.mark.parametrize(
    "document",
    [
        {"depths": {"deep": {"verify": ["AuthZ"]}}},
        {"depths": {}},
        {"depths": {"standard": {}}},
        {"depths": {"standard": {"verify": ["Infra"]}}},
        {"depths": {"standard": {"abuse_cases": 17}}},
        {"depths": {"standard": {"turn_budget": 40}}},
        {"test_cases": {"depths": {"standard": ["AuthZ"]}}},
        {"check_abuse_cases": ["ac-b-001"]},
    ],
)
def test_invalid_depth_values_are_rejected(home, document):
    write(home, "scan", "bad", {"schema_version": 1, **document})
    with pytest.raises(profiles.ProfileError, match="invalid scan profile"):
        profiles.resolve_scan("bad")


def test_a_case_cannot_be_both_checked_and_skipped(home):
    write(
        home, "scan", "bad", {"schema_version": 1, "check_abuse_cases": ["AC-B-001"], "skip_abuse_cases": ["AC-B-001"]}
    )
    with pytest.raises(profiles.ProfileError, match="AC-B-001 is listed both to check and to skip"):
        profiles.resolve_scan("bad")


def test_the_resolved_depth_values_stay_out_of_the_identity(home, monkeypatch):
    # The scan profile's own values count through the profile document; shipped values do not.
    before = profiles.resolve_scan("claude")["definition_sha256"]
    monkeypatch.setattr(depth_settings, "effective", lambda depth, **_: ({"budget": 99}, {"budget": "x"}))
    assert profiles.resolve_scan("claude")["definition_sha256"] == before
    write(home, "scan", "team", {"schema_version": 1, "depths": {"standard": {"abuse_cases": 4}}})
    assert profiles.resolve_scan("team")["definition_sha256"] != before


def test_required_aspects_join_the_selected_aspects_and_cannot_be_removed():
    assert profiles.add_required_aspects(False, ["AuthZ"]) == {"aspects": ["AuthZ"], "disable": []}
    setting = {"aspects": ["InputVal"], "disable": [REASON]}
    assert profiles.add_required_aspects(setting, ["DataProt", "AuthZ"]) == {
        "aspects": ["AuthZ", "InputVal", "DataProt"],
        "disable": [REASON],
    }
    for required in (None, []):
        assert profiles.add_required_aspects(False, required) is False
        assert profiles.add_required_aspects(setting, required) == setting


@pytest.mark.parametrize("value", ["true", 1, 0, "yes", None, []])
def test_non_boolean_test_cases_is_rejected_before_host_or_checkout(home, monkeypatch, capsys, value):
    from appsec_analyzer import hosts

    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not start"))
    write(home, "scan", "bad", {"schema_version": 1, "test_cases": value})
    assert cli.main(["assess", "--repo", "https://example.invalid/repo.git", "--profile", "bad"]) == 2
    assert "invalid scan profile (test_cases." in capsys.readouterr().err


def test_test_case_object_is_normalized_and_keeps_its_own_identity(home):
    write(
        home,
        "scan",
        "cases",
        {
            "schema_version": 1,
            "test_cases": {
                "aspects": ["AI", "DataProt", "AuthN"],
                "disable": [{"id": "TC-INFRA-01", "reason": "managed by platform"}, REASON],
            },
        },
    )
    resolved = profiles.resolve_scan("cases")
    assert resolved["settings"]["test_cases"] == {
        "aspects": ["AuthN", "DataProt", "AI"],
        "disable": [REASON, {"id": "TC-INFRA-01", "reason": "managed by platform"}],
    }
    write(home, "scan", "plain", {"schema_version": 1, "test_cases": True})
    assert resolved["definition_sha256"] != profiles.resolve_scan("plain")["definition_sha256"]


def test_a_test_case_object_without_aspects_keeps_the_depth_default(home):
    write(home, "scan", "cases", {"schema_version": 1, "test_cases": {"disable": [REASON]}})
    setting = profiles.resolve_scan("cases")["settings"]["test_cases"]
    assert setting == {"aspects": ["AuthN", "AuthZ", "InputVal", "AI"], "disable": [REASON]}
    assert profiles.session_test_cases(setting) == setting
    # Quick depth runs the survey only, so its disables have nothing to apply to.
    assert profiles.resolve_scan("cases", depth="quick")["settings"]["test_cases"] is False


def test_session_test_cases_form():
    assert profiles.session_test_cases(False) is False
    assert profiles.session_test_cases(None) is False
    assert profiles.session_test_cases(True) == {"aspects": [], "disable": []}
    assert profiles.session_test_cases(False, enabled=True) == {"aspects": [], "disable": []}
    assert profiles.session_test_cases(False, aspects=("DataProt", "AuthN")) == {
        "aspects": ["AuthN", "DataProt"],
        "disable": [],
    }
    setting = {"aspects": ["AuthN"], "disable": [REASON]}
    assert profiles.session_test_cases(setting) == setting
    # A flag can narrow the aspects but never removes a disable.
    assert profiles.session_test_cases(setting, aspects=("AuthZ",)) == {"aspects": ["AuthZ"], "disable": [REASON]}
    with pytest.raises(profiles.ProfileError):
        profiles.session_test_cases(False, aspects=("Infra",))


def test_disabling_a_required_test_case_is_refused():
    config = {"aspects": [], "disable": [REASON]}
    with pytest.raises(profiles.ProfileError, match="TC-CI-01 is required by the organization profile"):
        profiles.refuse_required_test_case_disable(config, ["TC-INFRA-01", "TC-CI-01"])
    for allowed in (False, True, config):
        profiles.refuse_required_test_case_disable(allowed, ["TC-INFRA-01"])
        profiles.refuse_required_test_case_disable(allowed, None)
    profiles.refuse_required_test_case_disable(True, ["TC-CI-01"])


def test_a_profile_inside_a_repository_cannot_enable_or_disable_test_cases(home, tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    path = repository / "scan.yaml"
    path.write_text(yaml.safe_dump({"schema_version": 1, "test_cases": {"disable": [REASON]}}))
    with pytest.raises(profiles.ProfileError, match="outside"):
        profiles.resolve_scan(str(path), repositories=[str(repository)])
    with pytest.raises(profiles.ProfileError, match="outside"):
        profiles.read_document(path, repositories=[str(repository)])


@pytest.mark.parametrize("change", [{"aspects": ["AuthN"]}, {"disable": [REASON]}])
def test_changing_aspects_or_disabled_test_cases_requires_a_new_run(home, tmp_path, monkeypatch, change):
    from runtime import assessment_state

    output = tmp_path / "out"
    output.mkdir()
    (output / assessment_state.STATE_NAME).write_text("{}")
    write(home, "scan", "cases", {"schema_version": 1, "test_cases": {"aspects": ["AuthN", "AuthZ"]}})
    saved = profiles.resolve_scan("cases")
    monkeypatch.setattr(assessment_state, "_read_state", lambda p: {"operator_profile": saved})
    assert profiles.restore_profile(profiles.resolve_scan("cases"), output, resume=True)
    write(home, "scan", "cases", {"schema_version": 1, "test_cases": {"aspects": ["AuthN", "AuthZ"], **change}})
    with pytest.raises(profiles.ProfileError, match="changed"):
        profiles.restore_profile(profiles.resolve_scan("cases"), output, resume=True)


def test_object_test_cases_reach_the_controller_as_aspects_and_profile(home, tmp_path, monkeypatch):
    setting = {"aspects": ["AuthZ", "AuthN"], "disable": [REASON]}
    write(home, "scan", "cases", {"schema_version": 1, "test_cases": setting})
    from appsec_analyzer import hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller as controller

    seen = {}

    def assess(args, **kwargs):
        seen.update(args=list(args), profile=kwargs["run_profile"])
        ns, _ = controller._assessment_argument_parser().parse_known_args(args)
        assert ns.test_cases is True and ns.test_case_aspects == ("AuthN", "AuthZ")
        return 0

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(controller, "assess_main", assess)
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    assert cli.main(["assess", "--repo", str(repo), "--profile", "cases"]) == 0
    assert "--test-cases" in seen["args"]
    assert seen["args"][seen["args"].index("--test-case-aspects") + 1] == "AuthN,AuthZ"
    from appsec_analyzer.profiles import session_test_cases

    assert session_test_cases(seen["profile"]["settings"]["test_cases"], enabled=True) == {
        "aspects": ["AuthN", "AuthZ"],
        "disable": [REASON],
    }


@pytest.mark.parametrize("enabled", [False, True])
def test_public_test_cases_reaches_controller_from_profile(home, tmp_path, monkeypatch, enabled):
    write(home, "scan", "cases", {"schema_version": 1, "test_cases": enabled})
    from appsec_analyzer import hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller as controller

    seen = {}

    def assess(args, **kwargs):
        seen.update(args=args, profile=kwargs["run_profile"])
        ns, _ = controller._assessment_argument_parser().parse_known_args(args)
        assert ns.test_cases is enabled
        return 0

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(controller, "assess_main", assess)
    repo = tmp_path / "repo"
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    assert cli.main(["assess", "--repo", str(repo), "--profile", "cases"]) == 0
    assert ("--test-cases" in seen["args"]) is enabled
    assert seen["profile"]["settings"]["test_cases"] is enabled


def test_test_cases_change_requires_new_run_and_older_snapshot_means_false(home, tmp_path, monkeypatch):
    from runtime import assessment_state

    output = tmp_path / "out"
    output.mkdir()
    (output / assessment_state.STATE_NAME).write_text("{}")
    # Quick depth runs the survey only, so its identity equals that of snapshots older than the setting.
    older = profiles.resolve_scan("claude", depth="quick")
    del older["settings"]["test_cases"]
    monkeypatch.setattr(assessment_state, "_read_state", lambda p: {"operator_profile": older})
    restored = profiles.restore_profile(profiles.resolve_scan("claude", depth="quick"), output, resume=True)
    assert restored["settings"]["test_cases"] is False
    write(home, "scan", "cases", {"schema_version": 1, "test_cases": True})
    with pytest.raises(profiles.ProfileError, match="changed"):
        profiles.restore_profile(profiles.resolve_scan("cases"), output, resume=True)


@pytest.mark.parametrize("command", ["assess", "profiles show", "profiles validate"])
@pytest.mark.parametrize("value", ["0", "-1", "17", "2.5", "true", "many"])
def test_invalid_max_parallel_is_rejected_before_host_or_checkout(home, monkeypatch, command, value):
    from appsec_analyzer import hosts

    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("host must not start"))
    args = command.split()
    args += (
        ["claude"] if args[0] == "profiles" else ["--repo", "https://example.invalid/repo.git", "--profile", "claude"]
    )
    with pytest.raises(SystemExit) as exc:
        cli.main([*args, f"--max-parallel={value}"])
    assert exc.value.code == 2


@pytest.mark.parametrize("name", ["claude", "codex", "codex-cli"])
@pytest.mark.parametrize("depth", profiles.DEPTHS)
def test_builtins_have_complete_roles_without_output_caps(home, name, depth):
    resolved = profiles.resolve_scan(name, depth=depth)
    assert set(resolved["models"]) == set(profiles.ROLES)
    assert all("max_output_tokens" not in row for row in resolved["models"].values())
    assert resolved["qualified"] is False
    if name in ("codex", "codex-cli"):
        assert resolved["models"]["recon_scanner"]["model"] == "gpt-6-luna"
        assert resolved["models"]["recon_scanner"]["reasoning_effort"] == "low"
        for role, settings in resolved["models"].items():
            if role != "recon_scanner":
                assert settings["model"] == "gpt-6.1-sol"
                assert settings["reasoning_effort"] == {"quick": "low", "standard": "medium", "thorough": "high"}[depth]


@pytest.mark.parametrize("base", ["codex", "codex-cli"])
@pytest.mark.parametrize("override", ["defaults", "roles"])
def test_operator_can_override_builtin_recon_model(home, base, override):
    definition = {"schema_version": 1, "base": base}
    settings = {"model": "gpt-sol", "reasoning_effort": "high"}
    definition[override] = settings if override == "defaults" else {"recon_scanner": settings}
    write(home, "model", "team", definition)
    write(home, "scan", "team", {"schema_version": 1, "model_profile": "team"})
    resolved = profiles.resolve_scan("team")
    assert resolved["models"]["recon_scanner"]["model"] == "gpt-6.1-sol"
    assert resolved["models"]["recon_scanner"]["reasoning_effort"] == "high"


@pytest.mark.parametrize(
    "patch",
    [
        {"budget": -1},
        {"budget": True},
        {"budget": float("inf")},
        *({"max_parallel": value} for value in (0, -1, 17, True, 2.0, "3")),
        *({"test_cases": value} for value in ("true", 1, 0, None, [])),
        *({"test_cases": value} for value in BAD_TEST_CASE_OBJECTS),
        {"model_profile": "../codex"},
        {"endpoint": "https://untrusted.invalid"},
        {"outputs": ["shell"]},
        {"schema_version": 2},
        {"abuse_case_files": "cases.yaml"},
        {"abuse_case_files": ["../cases.yaml"]},
        {"abuse_case_files": ["/private/cases.yaml"]},
        {"abuse_case_files": ["cases.json"]},
        {"abuse_case_files": ["cases.yaml\nspoofed"]},
        {"abuse_case_files": [f"cases-{n}.yaml" for n in range(33)]},
        {"report": {"attributes": {"team": "bad\nheader"}}},
    ],
)
def test_invalid_scan_profiles_fail_before_host_or_checkout(home, monkeypatch, patch):
    write(home, "scan", "bad", {"schema_version": 1, **patch})
    from appsec_analyzer import hosts

    cli._engine_imports()
    from runtime import remote_repositories

    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("no host"))
    monkeypatch.setattr(remote_repositories, "checkout_arguments", lambda *a: pytest.fail("no checkout"))
    assert cli.main(["assess", "--profile", "bad"]) == 2


@pytest.mark.parametrize(
    "body",
    [
        "schema_version: 1\nbudget: 10\nbudget: 20\n",
        "schema_version: 1\nmodel_profile: !!python/object/apply:os.system ['touch /tmp/forbidden-profile']\n",
        "schema_version: 1\nreport: &x {attributes: *x}\n",
        "[not, a, mapping]",
    ],
)
def test_ambiguous_or_executable_yaml_is_rejected(home, body):
    path = home / "profiles/bad.yaml"
    path.write_text(body)
    with pytest.raises(profiles.ProfileError):
        profiles.resolve_scan("bad")


def test_abuse_case_profile_selection_and_cli_replacement(home):
    write(home, "scan", "release", {"schema_version": 1, "abuse_case_files": ["policy/cases.yaml"]})
    saved = profiles.resolve_scan("release")
    assert saved["settings"]["abuse_case_files"] == ["policy/cases.yaml"]
    assert saved["origins"]["settings"]["abuse_case_files"].endswith("release.yaml")
    override = profiles.resolve_scan("release", abuse_case_files=["./review/one.yml", "review/two.yaml"])
    assert override["settings"]["abuse_case_files"] == ["review/one.yml", "review/two.yaml"]
    assert override["origins"]["settings"]["abuse_case_files"] == "CLI"
    assert override["definition_sha256"] != saved["definition_sha256"]
    assert profiles.resolve_scan("release", abuse_case_files=[])["settings"]["abuse_case_files"] == []


@pytest.mark.parametrize("command", ["assess"])
@pytest.mark.parametrize("override", [False, True])
def test_abuse_case_files_reach_controller_from_profile_or_cli(home, tmp_path, monkeypatch, command, override):
    from appsec_analyzer import hosts

    cli._engine_imports()
    from orchestrator import orchestration_controller
    from runtime import resolve_config

    write(home, "scan", "release", {"schema_version": 1, "abuse_case_files": ["policy/cases.yaml"]})
    observed = []
    snapshots = []
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)

    def assess(arguments, **kwargs):
        observed.extend(arguments)
        snapshots.append(kwargs["run_profile"])
        return 0

    monkeypatch.setattr(orchestration_controller, "assess_main", assess)
    subprocess.run(["git", "init", "-q", str(tmp_path / "repo")], check=True)
    args = [command, "--repo", str(tmp_path / "repo"), "--profile", "release", "--assessment-depth", "quick"]
    if override:
        args += ["--abuse-case-file", "review/a.yaml", "--abuse-case-file", "review/b.yml"]
    assert cli.main(args) == 0
    _, configuration_args = orchestration_controller._assessment_argument_parser().parse_known_args(observed)
    ns = resolve_config.build_parser().parse_args(configuration_args)
    expected = ["review/a.yaml", "review/b.yml"] if override else ["policy/cases.yaml"]
    assert ns.abuse_case_file == expected
    assert snapshots[0]["settings"]["abuse_case_files"] == expected
    assert not resolve_config.resolve_abuse_case_verification(ns, "quick")["skip_abuse_case_verification"]


@pytest.mark.parametrize("value", ["../case.yaml", "/tmp/case.yaml", "x/../../case.yaml", "x\\case.yaml", "case.py"])
def test_invalid_cli_abuse_case_path_stops_before_host(home, monkeypatch, value):
    from appsec_analyzer import hosts

    monkeypatch.setattr(hosts, "claude_preflight", lambda: pytest.fail("no host"))
    assert cli.main(["assess", "--abuse-case-file", value]) == 2


def test_error_never_echoes_unknown_field_value(home, capsys):
    write(home, "scan", "bad", {"schema_version": 1, "api_key": "synthetic-private-value"})
    assert cli.main(["profiles", "validate", "bad"]) == 2
    assert "synthetic-private-value" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "definition",
    [
        {"base": "another-user-profile"},
        {"base": "codex", "roles": {"unknown_role": {"model": "gpt-sol"}}},
        {"base": "codex", "defaults": {"model": "sonnet"}},
        {"base": "codex", "defaults": {"reasoning_effort": "none"}},
        {"base": "codex", "defaults": {"max_output_tokens": 128001}},
        {"base": "claude", "defaults": {"max_output_tokens": 1000}},
        {"base": "codex", "key_env": "ANOTHER_KEY"},
        {"base": "codex", "input_usd_per_million": 0.00001},
        {"base": "codex", "qualified": True},
    ],
)
def test_unknown_models_parameters_and_authority_are_rejected(home, definition):
    sample(home, model={"schema_version": 1, **definition})
    with pytest.raises(profiles.ProfileError):
        profiles.resolve_scan("release")


def test_explicit_output_cap_is_preserved(home):
    sample(
        home, model={"schema_version": 1, "base": "codex", "roles": {"stride_analyzer": {"max_output_tokens": 65536}}}
    )
    result = profiles.resolve_scan("release")
    assert profiles.api_profile(result["models"]["stride_analyzer"]).max_output_tokens == 65536
    assert profiles.api_profile(result["models"]["evidence_verifier"]).max_output_tokens is None


def test_symlinks_large_files_and_source_owned_profiles_are_rejected(home, tmp_path):
    sample(home)
    target = home / "profiles/release.yaml"
    (home / "profiles/link.yaml").symlink_to(target)
    with pytest.raises(profiles.ProfileError):
        profiles.resolve_scan("link")
    with pytest.raises(profiles.ProfileError, match="outside"):
        profiles.resolve_scan("release", repositories=[home])
    target.write_text("#" * (profiles.MAX_BYTES + 1))
    with pytest.raises(profiles.ProfileError, match="bounded"):
        profiles.resolve_scan("release")


def test_builtin_collision_and_model_file_symlink_fail(home, tmp_path):
    write(home, "scan", "codex", {"schema_version": 1})
    with pytest.raises(profiles.ProfileError, match="reserved"):
        profiles.resolve_scan("codex")
    with pytest.raises(profiles.ProfileError, match="reserved"):
        profiles.list_profiles()
    sample(home)
    model = home / "model-profiles/team-sol.yaml"
    external = tmp_path / "outside.yaml"
    model.rename(external)
    model.symlink_to(external)
    with pytest.raises(profiles.ProfileError, match="symlinks"):
        profiles.resolve_scan("release")


def test_profile_inspection_and_validation_do_not_need_credentials(home, monkeypatch, capsys):
    sample(home)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert cli.main(["profiles", "show", "release", "--budget", "7", "--max-parallel", "3"]) == 0
    shown = json.loads(capsys.readouterr().out)
    assert shown["settings"]["budget"] == 7
    assert shown["settings"]["max_parallel"] == 3
    assert shown["origins"]["settings"]["max_parallel"] == "CLI"
    assert cli.main(["profiles", "validate", "release"]) == 0
    assert json.loads(capsys.readouterr().out)["valid"]
    assert cli.main(["profiles", "list"]) == 0
    assert any(row["name"] == "team-sol" for row in json.loads(capsys.readouterr().out)["profiles"])


@pytest.mark.usefixtures("openai_metadata")
def test_public_cli_passes_effective_budget_exports_and_role_settings(home, tmp_path, monkeypatch, capsys):
    sample(home)
    cli._engine_imports()
    from orchestrator import orchestration_controller as controller

    seen = {}

    def assess(args, *, api_profile, run_profile):
        seen.update(args=args, profile=run_profile)
        return 0

    subprocess.run(["git", "init", "-q", str(tmp_path / "repo")], check=True)
    monkeypatch.setattr(controller, "assess_main", assess)
    assert (
        cli.main(
            [
                "assess",
                "--repo",
                str(tmp_path / "repo"),
                "--profile",
                "release",
                "--budget",
                "12",
                "--model",
                "gpt-sol",
                "--outputs",
                "html",
            ]
        )
        == 0
    )
    assert "Model budget limit:" not in capsys.readouterr().err
    assert "--html" in seen["args"] and "--sarif" not in seen["args"]
    assert seen["args"][seen["args"].index("--model") + 1] == "gpt-6.1-sol"
    assert seen["profile"]["models"]["recon_scanner"]["model"] == "gpt-6-luna"


def test_report_attributes_are_literal_text():
    cli._engine_imports()
    from shared.profile_metadata import render_attributes

    result = render_attributes({"team": "<script>alert(1)</script> | [link](https://bad.invalid)"})
    assert "<script>" not in result
    assert "[link]" not in result
    assert "&#124;" in result
    with pytest.raises(ValueError):
        render_attributes({"team": "line\nbreak"})


def test_model_alias_is_frozen_on_resume_and_changed_profile_is_rejected(home, tmp_path, monkeypatch):
    sample(home)
    original = profiles.resolve_scan("release")
    cli._engine_imports()
    from runtime import assessment_state

    output = tmp_path / "out"
    output.mkdir()
    (output / assessment_state.STATE_NAME).write_text("{}")
    monkeypatch.setattr(assessment_state, "_read_state", lambda p: {"operator_profile": original})
    registry = profiles.catalog()
    registry["aliases"]["gpt-sol"] = "gpt-6-astra"
    monkeypatch.setattr(profiles, "catalog", lambda: registry)
    changed = profiles.resolve_scan("release")
    assert changed["models"]["stride_analyzer"]["model"] == "gpt-6-astra"
    restored = profiles.restore_profile(changed, output, resume=True)
    assert restored["models"]["stride_analyzer"]["model"] == "gpt-6.1-sol"
    assert restored["models"]["stride_analyzer"]["input_usd_per_million"] == 2.5
    with pytest.raises(profiles.ProfileError, match="changed"):
        profiles.restore_profile(profiles.resolve_scan("release", budget=99), output, resume=True)
    with pytest.raises(profiles.ProfileError, match="changed"):
        profiles.restore_profile(profiles.resolve_scan("release", max_parallel=5), output, resume=True)


def test_catalog_prices_determine_role_reservations(home):
    sample(home)
    result = profiles.resolve_scan("release")
    assert profiles.call_reservation(result) > 1.28
    result["models"]["stride_analyzer"] = profiles.resolve_model({"model": "gpt-astra"}, "openai")
    assert profiles.call_reservation(result) > 6.4


def test_role_catalog_matches_the_controller():
    cli._engine_imports()
    from orchestrator.assessment_stage2 import RENDERER_MODEL_KEYS
    from orchestrator.orchestration_controller import SEMANTIC_ROLE_MODEL_KEYS

    from appsec_analyzer.model_roles import PROFILE_ROLE_ALIASES, profile_role

    assert set(profiles.ROLES) | set(PROFILE_ROLE_ALIASES) == set(SEMANTIC_ROLE_MODEL_KEYS) | set(RENDERER_MODEL_KEYS)
    # Aliases stay out of the profiles, so adding one leaves every profile's identity unchanged.
    assert not set(PROFILE_ROLE_ALIASES) & set(profiles.ROLES)
    assert set(PROFILE_ROLE_ALIASES.values()) <= set(profiles.ROLES)
    assert profile_role("test_case_investigator") == profile_role("open_reviewer") == "stride_analyzer"
    assert profile_role("threat_merger") == "threat_merger"
    for role, target in PROFILE_ROLE_ALIASES.items():
        assert SEMANTIC_ROLE_MODEL_KEYS[role] == SEMANTIC_ROLE_MODEL_KEYS[target]


def test_alias_roles_use_their_profile_roles_settings_and_stay_out_of_the_lineup(home, tmp_path):
    sample(
        home,
        model={
            "schema_version": 1,
            "base": "claude",
            "roles": {"stride_analyzer": {"model": "sonnet", "reasoning_effort": "high"}},
        },
    )
    selected = profiles.resolve_scan("release")
    assert "test_case_investigator" not in selected["models"]
    cli._engine_imports()
    from orchestrator import orchestration_controller as controller

    factory = controller._assessment_cli_host_factory(tmp_path, run_profile=selected)
    for role in ("test_case_investigator", "open_reviewer"):
        assert factory(role, "sonnet", 2).effort == "high"
    lineup, _ = controller._assessment_model_lines({"stride_model": "big"})
    assert "stride_analyzer" in lineup and "test_case_investigator" not in lineup and "open_reviewer" not in lineup


def test_custom_models_cannot_bypass_organization_opus_rule(home):
    sample(home, model={"schema_version": 1, "base": "claude", "roles": {"evidence_verifier": {"model": "opus"}}})
    resolved = profiles.resolve_scan("release")
    cli._engine_imports()
    with pytest.raises(profiles.ProfileError, match="Opus"):
        profiles.apply_runtime_profile(resolved, {"opus_disabled": True}, [])


def test_examples_validate_at_all_depths(home):
    for path in (resource_root() / "examples/profiles").glob("*.yaml"):
        for depth in profiles.DEPTHS:
            profiles.resolve_scan(str(path), depth=depth)


@pytest.mark.parametrize("model_profile", ["team-sol", "codex"])
def test_controller_dispatches_models_and_publishes_attributes(home, tmp_path, monkeypatch, model_profile):
    """Run the real offline controller through composition and publication."""
    sample(home)
    scan_path = home / "profiles/release.yaml"
    scan = yaml.safe_load(scan_path.read_text())
    scan["model_profile"] = model_profile
    attributes = {"team": "payments", "file": "release-2026", "repository_id": "review-label"}
    scan["report"]["attributes"] = attributes
    scan_path.write_text(yaml.safe_dump(scan))
    run = profiles.resolve_scan("release", depth="quick", outputs=["markdown", "yaml"], max_parallel=3)
    cli._engine_imports()
    from orchestrator import orchestration_controller as controller
    from runtime import multi_repo_scope

    from tests.test_multi_repo_assessment import FullHost
    from tests.test_multi_repo_controller import checkout

    root = tmp_path / "app"
    checkout(root)
    output = tmp_path / "out"
    host = FullHost()
    real_admit = multi_repo_scope.admit

    def admit(*args, **kwargs):
        host.scope = real_admit(*args, **kwargs)
        return host.scope

    dispatched = {}

    def factory(role, model, ceiling):
        dispatched[role] = model
        return host.factory(role, model, ceiling)

    monkeypatch.setattr(multi_repo_scope, "admit", admit)
    result = controller.assess_repositories(
        [
            "--repo",
            str(root),
            "--output",
            str(output),
            "--hard-budget",
            "30",
            "--assessment-depth",
            "quick",
            "--trust-mode",
            "trusted",
        ],
        host_factory=factory,
        progress=lambda text: None,
        run_profile=run,
    )
    assert result["status"] == "complete"
    assert dispatched["recon_scanner"] == "gpt-6-luna"
    assert dispatched["stride_analyzer"] == "gpt-6.1-sol"
    model = yaml.safe_load((output / "security-assessment.yaml").read_text())
    assert model["meta"]["report_attributes"] == attributes
    assert model["meta"]["model_configuration"]["recon_scanner"]["model"] == "gpt-6-luna"
    assert "payments" in (output / "security-assessment.md").read_text()
    state = json.loads((output / ".assessment-state.json").read_text())
    assert state["operator_profile"]["models"]["stride_analyzer"]["model"] == "gpt-6.1-sol"
    assert state["operator_profile"]["settings"]["max_parallel"] == 3


def test_validation_checks_unselected_depths(home, capsys):
    sample(
        home,
        model={
            "schema_version": 1,
            "base": "codex",
            "depths": {"quick": {"roles": {"stride_analyzer": {"model": "unknown"}}}},
        },
    )
    assert cli.main(["profiles", "validate", "release", "--assessment-depth", "standard"]) == 0
    capsys.readouterr()
    assert cli.main(["profiles", "validate", "release"]) == 2
    assert "model is not in" in capsys.readouterr().err


def test_parent_links_hardlinks_and_deep_yaml_are_rejected(home, tmp_path):
    import os

    sample(home)
    original = home / "profiles/release.yaml"
    link = tmp_path / "linked-profiles"
    link.symlink_to(original.parent, target_is_directory=True)
    with pytest.raises(profiles.ProfileError):
        profiles.read_document(link / "release.yaml")
    os.link(original, tmp_path / "hardlink.yaml")
    with pytest.raises(profiles.ProfileError):
        profiles.read_document(original)
    nested = tmp_path / "nested.yaml"
    nested.write_text("x: " + "[" * 5000 + "0" + "]" * 5000)
    with pytest.raises(profiles.ProfileError):
        profiles.read_document(nested)


def test_explicit_scan_path_does_not_use_user_model_file(home, tmp_path):
    sample(home)
    external = tmp_path / "team/profiles/release.yaml"
    external.parent.mkdir(parents=True)
    external.write_text((home / "profiles/release.yaml").read_text())
    with pytest.raises(profiles.ProfileError, match="missing"):
        profiles.resolve_scan(str(external))


def test_alias_resume_keeps_controller_identity_and_rejects_changed_budget(home, tmp_path, monkeypatch):
    sample(home)
    cli._engine_imports()
    from orchestrator import orchestration_controller as controller
    from runtime.assessment_jobs import AssessmentBudget
    from runtime.multi_repo_scope import admit

    from tests.test_multi_repo_controller import checkout

    root = tmp_path / "app"
    checkout(root)
    output = tmp_path / "out"
    scope = admit([str(root)], str(output), minimum=1)
    selected = profiles.resolve_scan("release", depth="quick")
    original_api = profiles.api_profile(selected["models"]["stride_analyzer"])
    arguments = ["--assessment-depth", "quick"]
    factory = lambda *args: pytest.fail("no model call needed")
    with controller._assessment_session(
        scope,
        arguments,
        budget=AssessmentBudget(30, 2, 100, 600),
        host_factory=factory,
        api_profile=original_api,
        run_profile=selected,
    ) as (_, state, _):
        identity = state.identity

    registry = profiles.catalog()
    registry["aliases"]["gpt-sol"] = "gpt-6-astra"
    monkeypatch.setattr(profiles, "catalog", lambda: registry)
    fresh = profiles.resolve_scan("release", depth="quick")
    fresh_api = profiles.api_profile(fresh["models"]["stride_analyzer"])
    restored = profiles.restore_profile(fresh, output, resume=True)
    with controller._assessment_session(
        scope,
        arguments,
        budget=AssessmentBudget(30, 2, 100, 600),
        resume=True,
        host_factory=factory,
        api_profile=fresh_api,
        run_profile=restored,
    ) as (cfg, state, _):
        assert state.identity == identity
        assert cfg["host_profile"]["model"] == "gpt-6.1-sol"
    with pytest.raises(profiles.ProfileError, match="changed"):
        profiles.restore_profile(profiles.resolve_scan("release", depth="quick", budget=31), output, resume=True)


def test_claude_role_effort_reaches_transport(home, tmp_path):
    sample(
        home,
        model={
            "schema_version": 1,
            "base": "claude",
            "roles": {"stride_analyzer": {"model": "sonnet", "reasoning_effort": "high"}},
        },
    )
    selected = profiles.resolve_scan("release")
    cli._engine_imports()
    from orchestrator import orchestration_controller as controller

    factory = controller._assessment_cli_host_factory(tmp_path, run_profile=selected)
    transport = factory("stride_analyzer", "sonnet", 2)
    assert transport.model == "sonnet"
    assert transport.effort == "high"
    assert transport.max_budget_usd == 2
