"""Outcomes of rules test cases and links from scanner findings to test cases (REQ-040)."""

from __future__ import annotations

import json

import pytest
from model import case_outcomes as tcr


@pytest.fixture(scope="module")
def catalog():
    return tcr.load_catalog()


def _case(catalog, case_id):
    return next(case for case in catalog["test_cases"] if case["id"] == case_id)


def _result(catalog, case_id, statuses, threats=(), disabled=None):
    results = tcr.evaluate(catalog, statuses, list(threats), disabled)
    return next(row for row in results if row["test_case_id"] == case_id)


def _all(catalog, case_id, status):
    return {rule: status for rule in _case(catalog, case_id)["starting_points"]["rules"]}


def test_only_rules_test_cases_get_an_outcome_without_a_model(catalog):
    results = tcr.evaluate(catalog, {}, [])
    assert {row["test_case_id"] for row in results} == {
        case["id"] for case in catalog["test_cases"] if case["mode"] == "rules"
    }


def test_control_needs_every_applicable_rule_satisfied(catalog):
    statuses = _all(catalog, "TC-CI-01", tcr.SATISFIED)
    row = _result(catalog, "TC-CI-01", statuses)
    assert row["outcome"] == "control"
    assert row["candidates"] == {"applicable": 2, "evidenced": 2}


def test_one_violated_rule_makes_a_finding_even_when_others_are_satisfied(catalog):
    statuses = _all(catalog, "TC-CI-01", tcr.SATISFIED)
    statuses["IAC-010"] = tcr.VIOLATED
    row = _result(catalog, "TC-CI-01", statuses)
    assert row["outcome"] == "finding"
    assert row["candidates"] == {"applicable": 2, "evidenced": 1}


def test_not_applicable_rules_do_not_count_as_candidates(catalog):
    statuses = _all(catalog, "TC-CI-01", tcr.NOT_APPLICABLE)
    assert _result(catalog, "TC-CI-01", statuses)["outcome"] == "not_applicable"
    statuses["IAC-015"] = tcr.SATISFIED
    assert _result(catalog, "TC-CI-01", statuses)["outcome"] == "control"


def test_a_missing_scanner_result_is_never_read_as_a_control(catalog):
    assert _result(catalog, "TC-CI-01", {})["outcome"] == "undecidable"
    partial = _result(catalog, "TC-CI-01", {"IAC-010": tcr.SATISFIED})
    assert partial["outcome"] == "partial"
    assert partial["candidates"] == {"applicable": 2, "evidenced": 1}


def test_a_disabled_test_case_reports_disabled_and_keeps_its_findings_linked(catalog):
    threat = {"id": "T-001", "config_check_id": "IAC-010"}
    tcr.annotate_threats([threat], catalog)
    row = _result(catalog, "TC-CI-01", _all(catalog, "TC-CI-01", tcr.SATISFIED), [threat], {"TC-CI-01": "central CI"})
    assert row["outcome"] == "disabled"
    assert row["reason"] == "central CI"
    assert row["finding_ids"] == ["T-001"]
    assert threat["test_case_ids"] == ["TC-CI-01"]


def test_annotation_links_rules_and_instances_and_leaves_other_threats_alone(catalog):
    jwt = {"id": "T-1", "source_check_id": "AUTHZ-005"}
    folded = {"id": "T-2", "instances": [{"config_check_id": "IAC-030"}, {"config_check_id": "IAC-031"}]}
    model_only = {"id": "T-3", "title": "Wallet top-up trusts the client amount"}
    unknown_rule = {"id": "T-4", "source_check_id": "NOT-A-RULE"}
    assert tcr.annotate_threats([jwt, folded, model_only, unknown_rule], catalog) == 2
    assert jwt["rule_ids"] == ["AUTHZ-005"] and jwt["test_case_ids"] == ["TC-AUTHN-02"]
    assert folded["rule_ids"] == ["IAC-030", "IAC-031"] and folded["test_case_ids"] == ["TC-SUPPLY-02"]
    assert "test_case_ids" not in model_only and "test_case_ids" not in unknown_rule


def test_statuses_follow_the_recorded_scanner_results(catalog):
    config = {"rules_evaluated": [{"check_id": "IAC-010", "status": "violated", "files": 1}]}
    coverage = {
        "rules_evaluated": [
            {"rule_id": "ARCH-SUPPLY-001", "status": "present", "applies": True},
            {"rule_id": "ARCH-TLS-001", "status": "missing", "applies": True},
            {"rule_id": "ARCH-JWT-001", "status": "missing", "applies": False},
        ]
    }
    statuses = tcr.rule_statuses(catalog, config, coverage)
    assert statuses == {
        "IAC-010": tcr.VIOLATED,
        "ARCH-SUPPLY-001": tcr.SATISFIED,
        "ARCH-TLS-001": tcr.VIOLATED,
        "ARCH-JWT-001": tcr.NOT_APPLICABLE,
    }


def test_a_skipped_config_scan_makes_iac_rules_not_applicable_not_satisfied(catalog):
    skipped = {"parse_error": "skipped: no IaC surface detected", "findings": []}
    statuses = tcr.rule_statuses(catalog, skipped, None)
    assert statuses["IAC-010"] == tcr.NOT_APPLICABLE
    assert "ARCH-SUPPLY-001" not in statuses
    assert _result(catalog, "TC-CI-01", statuses)["outcome"] == "not_applicable"


def test_build_block_reads_sidecars_and_tolerates_missing_or_broken_ones(catalog, tmp_path):
    threats = [{"id": "T-1", "config_check_id": "IAC-010"}]
    block = tcr.build_block(tmp_path, threats)
    assert block["catalog_version"] == catalog["catalog_version"]
    assert {row["outcome"] for row in block["results"]} == {"undecidable"}
    assert threats[0]["test_case_ids"] == ["TC-CI-01"]

    (tmp_path / ".config-scan-findings.json").write_text("{not json", encoding="utf-8")
    assert {row["outcome"] for row in tcr.build_block(tmp_path, [])["results"]} == {"undecidable"}

    document = {"rules_evaluated": [{"check_id": "IAC-010", "status": "satisfied", "files": 2}]}
    (tmp_path / ".config-scan-findings.json").write_text(json.dumps(document), encoding="utf-8")
    ci = next(row for row in tcr.build_block(tmp_path, [])["results"] if row["test_case_id"] == "TC-CI-01")
    assert ci["outcome"] == "partial"


def test_an_invalid_catalog_is_refused(tmp_path):
    broken = tmp_path / "test-cases.yaml"
    broken.write_text("version: 1\n", encoding="utf-8")
    with pytest.raises(ValueError):
        tcr.load_catalog(broken)


def _block_validator():
    from pathlib import Path

    import yaml
    from jsonschema import Draft202012Validator

    schema = yaml.safe_load(
        (Path(__file__).resolve().parents[1] / "schemas" / "threat-model.output.schema.yaml").read_text(
            encoding="utf-8"
        )
    )
    return Draft202012Validator(schema["properties"]["test_case_results"])


def test_the_result_block_matches_the_output_schema(tmp_path):
    validator = _block_validator()
    assert list(validator.iter_errors(tcr.build_block(tmp_path, []))) == []


@pytest.mark.parametrize(
    "change",
    [
        lambda block: block["results"][0].update(outcome="secure"),
        lambda block: block["results"][0].update(extra="field"),
        lambda block: block["results"][0]["rules"][0].update(status="passed"),
        lambda block: block["results"][0].pop("reason"),
    ],
)
def test_the_output_schema_rejects_malformed_results(tmp_path, change):
    block = tcr.build_block(tmp_path, [])
    change(block)
    assert list(_block_validator().iter_errors(block))


def test_appendix_lists_every_catalog_test_case_and_never_shows_an_unexamined_one_as_a_control(tmp_path):
    from renderers import compose_threat_model as compose

    from tests.test_compose_threat_model_cov import _mk_ctx

    catalog = tcr.load_catalog()
    block = tcr.build_block(tmp_path, [])
    ctx = _mk_ctx(tmp_path, yaml_data={"test_case_results": block})
    out = compose._render_appendix_test_cases(ctx, None, {})
    assert out.startswith('<a id="appendix-test-cases"></a>\n## Appendix: Security Test Cases')
    for case in catalog["test_cases"]:
        assert f'<a id="{case["id"].lower()}"></a>' in out
    assert "| [TC-AUTHZ-01](#tc-authz-01) | AuthZ | Not examined |" in out
    assert "| [TC-CI-01](#tc-ci-01) | SupplyChain | Undecidable |" in out
    assert "Control evidenced" not in out


def test_appendix_is_absent_without_results(tmp_path):
    from renderers import compose_threat_model as compose

    from tests.test_compose_threat_model_cov import _mk_ctx

    assert compose._render_appendix_test_cases(_mk_ctx(tmp_path, yaml_data={}), None, {}) == ""
