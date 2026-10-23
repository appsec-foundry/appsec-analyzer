"""What each assessment depth does: shipped defaults, organization defaults, and scan profile values (REQ-018)."""

from __future__ import annotations

import argparse

import pytest
import yaml
from jsonschema import Draft202012Validator
from model import resolve_abuse_cases
from runtime import resolve_config

from appsec_analyzer import depth_settings, resource_root

DEPTHS = ("quick", "standard", "thorough")


def _schema(name):
    return yaml.safe_load((resource_root() / "schemas" / name).read_text())


def test_the_shipped_file_reproduces_each_depth_before_it_existed():
    limits = resolve_abuse_cases.load_limits()
    expected = {
        "quick": (0, 0, False, False, 10),
        "standard": (limits["descriptive_candidates_standard"], 0, False, True, 20),
        "thorough": (
            limits["descriptive_candidates_thorough"],
            limits["descriptive_candidates_derived"],
            True,
            True,
            40,
        ),
    }
    for depth in DEPTHS:
        values = depth_settings.shipped(depth)
        keys = ("abuse_cases", "derived_abuse_cases", "architect_review", "actor_discovery", "budget")
        assert tuple(values[key] for key in keys) == expected[depth], depth
    assert [depth_settings.shipped(depth)["verify"] for depth in DEPTHS] == [
        [],
        ["AuthZ"],
        ["AuthZ", "InputVal", "DataProt", "AI"],
    ]


@pytest.mark.parametrize("depth", DEPTHS)
def test_the_resolver_decides_as_before_with_the_shipped_values(depth):
    ns = argparse.Namespace(no_architect_review=False, architect_review=False, architect_model=None)
    values = depth_settings.shipped(depth)
    assert resolve_config.resolve_architect_review(ns, depth, False) == resolve_config.resolve_architect_review(
        ns, depth, False, values["architect_review"]
    )
    assert resolve_config.resolve_abuse_case_verification(ns, depth) == resolve_config.resolve_abuse_case_verification(
        ns, depth, values
    )


def test_profiles_carry_the_same_depth_block_as_the_shipped_schema():
    block = _schema("assessment-depths.schema.yaml")["$defs"]["depth_settings"]
    assert _schema("scan-profile.schema.yaml")["$defs"]["depth_settings"] == block
    assert _schema("org-profile.schema.yaml")["$defs"]["depth_settings"] == block
    shipped = yaml.safe_load((resource_root() / depth_settings.SHIPPED).read_text())
    assert not list(Draft202012Validator(_schema("assessment-depths.schema.yaml")).iter_errors(shipped))
    # Technical limits are not settings.
    assert set(block["properties"]) == set(depth_settings.KEYS)


def test_the_scan_profile_wins_over_the_organization_which_wins_over_the_file():
    organization = {"standard": {"abuse_cases": 5, "architect_review": True}, "quick": {"budget": 7}}
    scan = {"standard": {"abuse_cases": 2}}
    values, origins = depth_settings.effective("standard", organization=organization, scan=scan)
    assert (values["abuse_cases"], origins["abuse_cases"]) == (2, "scan profile")
    assert (values["architect_review"], origins["architect_review"]) == (True, "organization profile")
    assert (values["budget"], origins["budget"]) == (20, "analyzer default")
    # One depth's values leave the others alone.
    assert depth_settings.effective("thorough", organization=organization, scan=scan)[0] == depth_settings.shipped(
        "thorough"
    )
    assert depth_settings.effective("quick", organization=organization)[0]["budget"] == 7


def _ns(**flags):
    names = ("no_architect_review", "architect_review", "no_abuse_cases", "abuse_cases", "dry_run")
    return argparse.Namespace(
        architect_model=None, abuse_case_file=[], only_abuse_case=[], **dict.fromkeys(names, False) | flags
    )


def test_organization_and_team_values_decide_the_switches_and_flags_still_win():
    cfg = {"assessment_depth": "standard", "org_profile_depths": {"standard": {"architect_review": True}}}
    out = resolve_config.resolve_depth_settings(_ns(), cfg, {"standard": {"abuse_cases": 0}})
    assert out["architect_review"] and out["architect_label"].endswith("(sonnet, organization profile, standard depth)")
    assert out["skip_abuse_case_verification"]
    assert out["abuse_case_label"] == "skipped (scan profile: no abuse cases at standard depth)"
    flagged = resolve_config.resolve_depth_settings(_ns(no_architect_review=True, abuse_cases=True), cfg, None)
    assert not flagged["architect_review"] and not flagged["skip_abuse_case_verification"]
    # Model-derived cases alone keep the stage on.
    derived = resolve_config.resolve_depth_settings(
        _ns(), {"assessment_depth": "quick"}, {"quick": {"derived_abuse_cases": 2}}
    )
    assert not derived["skip_abuse_case_verification"]


def test_the_dialogue_budget_follows_the_organization_and_then_the_scan_profile(tmp_path, monkeypatch):
    import subprocess

    from appsec_analyzer import cli

    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(depth_settings, "organization_depths", lambda *a: {"standard": {"budget": 33}})
    ns = cli._parser().parse_args(["assess", "--repo", str(repo), "--interactive-launch"])
    cli._prepare_profile(ns)
    assert ns.hard_budget == 33
    profiles = tmp_path / "config" / "appsec-analyzer" / "profiles"
    profiles.mkdir(parents=True)
    (profiles / "team.yaml").write_text("schema_version: 1\ndepths:\n  standard:\n    budget: 12\n")
    ns = cli._parser().parse_args(["assess", "--repo", str(repo), "--interactive-launch", "--profile", "team"])
    cli._prepare_profile(ns)
    assert ns.hard_budget == 12


def test_the_library_ids_that_a_scan_profile_can_check_are_known_before_any_model_call():
    from orchestrator import orchestration_controller as controller

    ids = controller._library_abuse_case_ids()
    assert {"AC-T-001", "AC-B-001"} <= ids and not any(cid.startswith(("ORG-AC", "REPO-AC")) for cid in ids)
