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


# --- model investigations (REQ-040 pilot) ------------------------------------------


def _cand(status, origin="pre-check", confirmed=False, reason=None):
    return {"status": status, "origin": origin, "confirmed": confirmed, "reason": reason}


def _outcome(catalog, candidates, **kwargs):
    return tcr.component_outcome(_case(catalog, "TC-AUTHZ-01"), "api", candidates, **kwargs)


@pytest.mark.parametrize(
    ("candidates", "unexamined", "outcome", "basis", "reason"),
    [
        ([_cand("weakness", confirmed=True), _cand("control")], 0, "finding", "deterministic", "weakness at 1 of 2"),
        ([_cand("weakness"), _cand("control", confirmed=True)], 0, "finding", "model", "control evidenced at 1"),
        ([_cand("control", confirmed=True)] * 2, 0, "control", "deterministic", "control evidenced at all 2"),
        ([_cand("control", confirmed=True), _cand("neither")], 0, "partial", "deterministic", "1 of 2"),
        # Overflow never yields a control, and an unexamined set alone is undecidable.
        ([_cand("control", confirmed=True)] * 2, 3, "partial", "deterministic", "2 of 5 candidate locations; 3 not"),
        ([], 2, "undecidable", "model", "2 of 2 candidate locations did not fit"),
        # A control over a candidate set the model alone defined is model-evidenced.
        ([_cand("control", origin="model", confirmed=True)], 0, "control", "model", "all 1"),
        ([_cand("control"), _cand("control", confirmed=True)], 0, "control", "model", "all 2"),
        (
            [_cand("undecidable", reason=tcr.DOCUMENTATION_REASON), _cand("neither")],
            0,
            "undecidable",
            "model",
            "1 of 2",
        ),
        ([_cand("rejected"), _cand("rejected")], 0, "no_finding", "model", "every candidate location was rejected"),
        ([_cand("neither"), _cand("rejected")], 0, "no_finding", "model", "no weakness or control at 1 examined"),
        ([], 0, "no_finding", "model", "no candidate location"),
    ],
)
def test_component_outcome_table(catalog, candidates, unexamined, outcome, basis, reason):
    row = _outcome(catalog, candidates, unexamined=unexamined)
    assert (row["outcome"], row["evidence_basis"]) == (outcome, basis)
    assert reason in row["reason"]
    assert row["candidates"]["applicable"] == sum(c["status"] != "rejected" for c in candidates) + unexamined
    assert row["candidates"]["unexamined"] == unexamined
    assert list(_block_validator().iter_errors({"catalog_version": "1", "results": [row]})) == []


def test_the_proposed_outcome_is_kept_only_when_it_differs(catalog):
    assert "proposed_outcome" not in _outcome(catalog, [_cand("neither")], proposed_outcome="no_finding")
    assert _outcome(catalog, [_cand("neither")], proposed_outcome="control")["proposed_outcome"] == "control"


# A route whose handler reads an object by identifier without comparing its owner.
_FACTS = {
    "files": ["server.js"],
    "routes": {
        rid: {
            "route_id": rid,
            "method": "GET",
            "path": f"/api/{name}/:id",
            "handler_file": "server.js",
            "handler_line": line,
            "handler_module": None,
            "chain": [],
            "handler_read": True,
            "object_access": True,
            "ownership_predicate": rid == "R-003",
        }
        for rid, name, line in (("R-001", "orders", 4), ("R-002", "orders", 9), ("R-003", "invoices", 12))
    },
    "components": {"api": {"files": ["server.js"], "route_ids": ["R-001", "R-002", "R-003"]}},
}
PC1, PC3 = "pc-" + "1" * 16, "pc-" + "3" * 16
_PRECHECK = [
    {"candidate_id": PC1, "origin": "pre-check", "anchor": {"file": "server.js", "line": 4}, "route_id": "R-001"},
    {"candidate_id": PC3, "origin": "pre-check", "anchor": {"file": "server.js", "line": 12}, "route_id": "R-003"},
]
_EVIDENCE = {"repository_id": "repo-" + "1" * 16, "file": "server.js", "line": 5, "sha256": "a" * 64}


def _answer(first, third, finding_ids=()):
    return {
        "test_case_id": "TC-AUTHZ-01",
        "proposed_outcome": "control",
        "reason": "model text that never reaches a result",
        "candidates": [
            {
                "candidate_id": PC1,
                "origin": "pre-check",
                "evidence": [_EVIDENCE],
                "finding_ids": list(finding_ids),
                **first,
            },
            {"candidate_id": PC3, "origin": "pre-check", "evidence": [_EVIDENCE], "finding_ids": [], **third},
        ],
    }


def test_a_contradicted_control_becomes_undecidable_and_a_confirmed_one_deterministic(catalog):
    case = _case(catalog, "TC-AUTHZ-01")
    control = {"status": "control", "control_kind": "code"}
    records, checks = tcr.assess_candidates(case, _answer(control, control), _PRECHECK, _FACTS)
    first, third = records
    assert (first["status"], first["contradicted"], first["reason"]) == ("undecidable", True, tcr_owner_missing())
    assert (third["status"], third["confirmed"]) == ("control", True)
    assert {(row["candidate_id"], row["check"], row["result"]) for row in checks} == {
        (PC1, "route-registered", "confirmed"),
        (PC1, "handler-chain-lacks-guard", "contradicted"),
        (PC3, "route-registered", "confirmed"),
        (PC3, "handler-chain-lacks-guard", "confirmed"),
    }
    row = tcr.component_outcome(case, "api", records, post_checks=checks)
    assert (row["outcome"], row["evidence_basis"]) == ("partial", "deterministic")
    assert "model text" not in json.dumps(row)


def tcr_owner_missing():
    from model.case_postchecks import OWNER_MISSING

    return OWNER_MISSING


def test_a_documentation_control_is_undecidable_and_runs_no_check(catalog):
    case = _case(catalog, "TC-AUTHZ-01")
    doc = {"status": "control", "control_kind": "code", "evidence": [{**_EVIDENCE, "file": "docs/authz.md"}]}
    records, checks = tcr.assess_candidates(case, _answer(doc, {"status": "neither"}), _PRECHECK, _FACTS)
    assert (records[0]["status"], records[0]["reason"]) == ("undecidable", tcr.DOCUMENTATION_REASON)
    assert checks == []
    assert tcr.is_documentation("README.rst") and tcr.is_documentation("docs/guide/auth.js")
    assert not tcr.is_documentation("src/docs.js")


def test_investigation_results_drop_contradicted_findings_and_list_unreviewed_variants(catalog):
    reply = {
        "test_cases": [_answer({"status": "weakness"}, {"status": "weakness"}, ["api-001"])],
        "findings": [
            {"local_id": "api-001", "test_case_ids": ["TC-AUTHZ-01"], "candidate_ids": [PC1]},
            {"local_id": "api-002", "test_case_ids": ["TC-AUTHZ-01"], "candidate_ids": [PC3]},
        ],
    }
    reply["test_cases"][0]["candidates"][1]["finding_ids"] = ["api-002"]
    result = tcr.investigation_results(
        reply, "api", precheck={"TC-AUTHZ-01": _PRECHECK}, overflow={"TC-AUTHZ-01": 1}, facts=_FACTS
    )
    row = result["results"][0]
    # R-003 compares the owner, so its weakness claim is contradicted and its finding leaves the merge input.
    assert result["dropped_finding_ids"] == ["api-002"]
    assert (row["outcome"], row["finding_ids"], row["proposed_outcome"]) == ("finding", ["api-001"], "control")
    assert row["candidates"]["unexamined"] == 1 and row["candidates"]["undecidable"] == 1
    assert row["unreviewed_variants"] == {"count": 1, "route_ids": ["R-002"]}
    assert list(_block_validator().iter_errors({"catalog_version": "1", "results": [row]})) == []


def test_a_replaced_investigation_is_undecidable_with_a_fixed_reason(catalog):
    row = tcr.replacement_result(_case(catalog, "TC-AUTHZ-01"), "api", "budget", unexamined=4)
    assert (row["outcome"], row["reason"]) == ("undecidable", tcr.REPLACEMENT_REASONS["budget"])
    with pytest.raises(ValueError):
        tcr.replacement_result(_case(catalog, "TC-AUTHZ-01"), "api", "anything")


@pytest.mark.parametrize(
    "change",
    [
        lambda row: row.pop("component_id"),
        lambda row: row["post_checks"].append({"candidate_id": "x", "check": "route-registered"}),
        lambda row: row.update(proposed_outcome="secure"),
        lambda row: row["candidates"].update(unexamined=-1),
    ],
)
def test_the_output_schema_rejects_malformed_component_results(catalog, change):
    row = _outcome(catalog, [_cand("control", confirmed=True)])
    change(row)
    assert list(_block_validator().iter_errors({"catalog_version": "1", "results": [row]}))
