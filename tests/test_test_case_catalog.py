"""The test case catalog stays consistent with the rules, controls, and abuse cases it names (REQ-040)."""

from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def _load(relative: str):
    return yaml.safe_load((ROOT / relative).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def catalog():
    return _load("data/test-cases.yaml")


@pytest.fixture(scope="module")
def validator():
    return Draft202012Validator(_load("schemas/test-cases.schema.yaml"))


def _ids(node):
    found = []
    if isinstance(node, dict):
        if isinstance(node.get("id"), str):
            found.append(node["id"])
        for value in node.values():
            found.extend(_ids(value))
    elif isinstance(node, list):
        for value in node:
            found.extend(_ids(value))
    return found


def _shipped_rules():
    rules = set()
    for name in (
        "config-iac-checks.yaml",
        "source-auth-checks.yaml",
        "crypto-checks.yaml",
        "architecture-coverage-rules.yaml",
    ):
        rules.update(_ids(_load(f"data/{name}")))
    # Rules defined in code appear in the STRIDE table of the merge step.
    source = (ROOT / "scripts" / "model" / "merge_threats.py").read_text(encoding="utf-8")
    table = source.split("_AUTHZ_TO_STRIDE: dict[str, str] = {", 1)[1].split("\n}", 1)[0]
    rules.update(re.findall(r'"([A-Z][A-Z0-9-]+)":', table))
    return rules


def test_catalog_matches_its_schema(catalog, validator):
    assert sorted(validator.iter_errors(catalog), key=str) == []


def test_ids_are_unique_and_aspects_are_declared(catalog):
    ids = [case["id"] for case in catalog["test_cases"]]
    assert len(ids) == len(set(ids))
    aspects = {aspect["id"] for aspect in catalog["aspects"]}
    assert {case["aspect"] for case in catalog["test_cases"]} <= aspects


def test_every_shipped_rule_is_a_starting_point_or_recorded_as_unmapped(catalog):
    mapped = {rule for case in catalog["test_cases"] for rule in case["starting_points"]["rules"]}
    unmapped = {entry["rule"] for entry in catalog["unmapped_rules"]}
    shipped = _shipped_rules()
    assert sorted(shipped - mapped - unmapped) == []
    assert sorted((mapped | unmapped) - shipped) == []
    assert not mapped & unmapped


def test_controls_and_abuse_cases_exist(catalog):
    controls = {control["name"] for control in _load("data/architectural-controls.yaml")["controls"]}
    abuse = set(_ids(_load("data/abuse-cases/technical.yaml"))) | set(_ids(_load("data/abuse-cases/business.yaml")))
    for case in catalog["test_cases"]:
        assert set(case["controls"]) <= controls, case["id"]
        assert set(case["starting_points"].get("abuse_cases", [])) <= abuse, case["id"]


def test_each_investigated_aspect_has_one_goal_test_case_without_a_cwe(catalog):
    goals = [case for case in catalog["test_cases"] if case.get("goal")]
    assert [case["id"] for case in goals] == ["TC-AUTHZ-06", "TC-INPUT-07", "TC-DATA-05", "TC-AI-05"]
    for case in catalog["test_cases"]:
        # A goal starts from no rule or fact, and a CWE would narrow its search.
        if case.get("goal"):
            assert case["mode"] == "model" and not case["cwe"], case["id"]
            assert not case["starting_points"]["rules"] and not case["starting_points"].get("facts"), case["id"]
        else:
            assert case["cwe"], case["id"]


def test_every_ai_test_case_but_the_goal_names_its_owasp_llm_categories(catalog):
    # A goal finding may belong to any category; its own title decides where the AI exposure section lists it.
    for case in catalog["test_cases"]:
        if case["aspect"] == "AI":
            assert bool(case.get("owasp_llm")) is not bool(case.get("goal")), case["id"]


def test_a_verification_finding_carries_the_owasp_llm_categories_of_its_test_cases(catalog):
    """The AI exposure section lists a finding only by its categories (juice-shop 2026-10: a TC-AI-01 finding was missing)."""
    from orchestrator import assessment_test_cases as pilot

    cases = {case["id"]: case for case in catalog["test_cases"]}

    def row(test_case_ids, **reply):
        finding = {"local_id": "F-1", "candidate_ids": [], "test_case_ids": test_case_ids, **reply}
        return pilot._finding(finding, "TCF-001", "api", "AI", cases)

    assert row(["TC-AI-01", "TC-AI-02"])["owasp_llm_ids"] == ["LLM01", "LLM05"]
    # The reply's own categories come first, and each category appears once.
    assert row(["TC-AI-01"], owasp_llm_ids=["LLM06", "LLM01"])["owasp_llm_ids"] == ["LLM06", "LLM01"]
    # A goal or non-AI test case adds none.
    assert "owasp_llm_ids" not in row(["TC-AI-05"])
    assert "owasp_llm_ids" not in row(["TC-AUTHZ-01"])


def test_every_route_and_site_fact_and_site_check_has_an_evaluator(catalog):
    from model import case_candidates

    # A misspelled fact or site would silently select or confirm nothing.
    kinds, _ = case_candidates.site_kinds()
    known = set(case_candidates._ROUTE_FACTS) | {f"code_sites.{kind}" for kind in kinds}
    for case in catalog["test_cases"]:
        facts = case["starting_points"].get("facts") or []
        assert {fact for fact in facts if fact.startswith(("route_inventory.", "code_sites."))} <= known, case["id"]
        sites = {entry.get("site") for entry in case["post"] if entry["check"] == "site-reached"}
        assert None not in sites and sites <= {*kinds, "any"}, case["id"]


def test_rules_mode_cases_are_driven_by_rules_alone(catalog):
    for case in catalog["test_cases"]:
        if case["mode"] == "rules":
            assert case["starting_points"]["rules"], case["id"]
            assert not case["post"], case["id"]
            assert {entry["signal"] for entry in case["applies_when"]} == {"iac_files"}, case["id"]
            assert all(entry.get("iac_type") for entry in case["applies_when"]), case["id"]


@pytest.mark.parametrize(
    "change",
    [
        lambda case: case.update(mode="guess"),
        lambda case: case.update(stride=[]),
        lambda case: case.update(fixtures="elsewhere/"),
        lambda case: case["post"].append({"check": "run-model-written-regex"}),
        lambda case: case.update(unexpected="field"),
        lambda case: case.update(owasp_llm=["LLM11"]),
        lambda case: case.pop("objective"),
    ],
)
def test_schema_rejects_malformed_cases(catalog, validator, change):
    broken = copy.deepcopy(catalog)
    change(next(case for case in broken["test_cases"] if case["id"] == "TC-AUTHZ-01"))
    assert list(validator.iter_errors(broken))
