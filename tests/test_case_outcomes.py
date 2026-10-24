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
    assert out.startswith('<a id="appendix-verification-items"></a>\n## Appendix: Verification Items')
    for case in catalog["test_cases"]:
        assert f'<a id="{case["id"].lower()}"></a>' in out
    assert "| [TC-AUTHZ-01](#tc-authz-01) | AuthZ | Not examined |" in out
    assert "| [TC-CI-01](#tc-ci-01) | SupplyChain | Undecidable |" in out
    assert "Control evidenced" not in out


def test_appendix_is_absent_without_results(tmp_path):
    from renderers import compose_threat_model as compose

    from tests.test_compose_threat_model_cov import _mk_ctx

    assert compose._render_appendix_test_cases(_mk_ctx(tmp_path, yaml_data={}), None, {}) == ""


def _pilot(catalog, tmp_path):
    """A pilot sidecar with a finding, a partial and a no-finding result of the `api` component."""
    rows = [
        tcr.component_outcome(_case(catalog, "TC-AUTHZ-01"), "api", [_cand("weakness")], finding_ids=["TCF-001"]),
        tcr.component_outcome(_case(catalog, "TC-AUTHZ-02"), "api", [_cand("control"), _cand("neither")]),
        tcr.component_outcome(_case(catalog, "TC-AUTHZ-03"), "api", [_cand("neither")]),
    ]
    finding = {
        "id": "TCF-001",
        "component_id": "api",
        "aspect": "AuthZ",
        "test_case_ids": ["TC-AUTHZ-01"],
        "title": "Order [access](javascript:alert(1)) | lacks an owner check",
        "stride": "Elevation of Privilege",
        "risk": "High",
        "cwe": "CWE-639",
        "evidence": {"file": "server.js", "line": 8},
    }
    document = {"schema_version": 1, "aspects": ["AuthZ"], "results": rows, "findings": [finding]}
    (tmp_path / tcr.PILOT_SIDECAR).write_text(json.dumps(document), encoding="utf-8")
    return document


def test_build_block_appends_the_pilot_rows_after_the_unchanged_rules_rows(catalog, tmp_path):
    import yaml
    from jsonschema import Draft202012Validator

    rules = tcr.build_block(tmp_path, [])["results"]
    document = _pilot(catalog, tmp_path)
    block = tcr.build_block(tmp_path, [])
    assert block["results"] == rules + document["results"]
    assert list(_block_validator().iter_errors(block)) == []
    assert tcr.pilot_findings(tmp_path) == document["findings"]
    schema = yaml.safe_load((tcr.ROOT / "schemas" / "threat-model.output.schema.yaml").read_text(encoding="utf-8"))
    findings = schema["properties"]["test_case_findings"]
    assert list(Draft202012Validator(schema).descend(document["findings"], findings)) == []
    malformed = [{**document["findings"][0], "id": "T-001", "test_case_ids": []}]
    assert len(list(Draft202012Validator(schema).descend(malformed, findings))) == 2
    (tmp_path / tcr.PILOT_SIDECAR).unlink()
    assert tcr.pilot_findings(tmp_path) == []


def test_appendix_shows_one_row_per_component_and_never_words_partial_or_no_finding_as_a_control(catalog, tmp_path):
    from renderers import compose_threat_model as compose

    from tests.test_compose_threat_model_cov import _mk_ctx

    _pilot(catalog, tmp_path)
    model = {"test_case_results": tcr.build_block(tmp_path, []), "components": [{"id": "api", "name": "Order API"}]}
    out = compose._render_appendix_test_cases(_mk_ctx(tmp_path, yaml_data=model), None, {})
    assert "| [TC-AUTHZ-01](#tc-authz-01) · Order API | AuthZ | Finding |" in out
    assert "| [TC-AUTHZ-02](#tc-authz-02) · Order API | AuthZ | Partial, not a control |" in out
    assert "| [TC-AUTHZ-03](#tc-authz-03) · Order API | AuthZ | No finding, no control |" in out
    assert "| [TC-AUTHZ-04](#tc-authz-04) | AuthZ | Not examined |" in out
    assert "Control evidenced" not in out and "Partial control" not in out
    assert "Outcome for Order API: Finding." in out and "Findings: TCF-001" in out
    assert "Evidenced by model review only" in out


def test_appendix_lists_components_a_test_case_does_not_apply_to_in_one_row(catalog, tmp_path):
    from renderers import compose_threat_model as compose

    from tests.test_compose_threat_model_cov import _mk_ctx

    _pilot(catalog, tmp_path)
    case = _case(catalog, "TC-AUTHZ-04")
    rows = []
    for component in ("api", "store", "ci"):
        row = tcr.component_outcome(case, component, [])
        row.update(
            outcome="not_applicable", reason="no applicability signal of the test case shows in the examined code"
        )
        rows.append(row)
    block = tcr.build_block(tmp_path, [])
    block["results"] += rows
    names = [{"id": "api", "name": "Order API"}, {"id": "store", "name": "Store"}, {"id": "ci", "name": "CI"}]
    out = compose._render_appendix_test_cases(
        _mk_ctx(tmp_path, yaml_data={"test_case_results": block, "components": names}), None, {}
    )
    assert "| [TC-AUTHZ-04](#tc-authz-04) · 3 components | AuthZ | Not applicable | " in out
    assert out.count("[TC-AUTHZ-04](#tc-authz-04)") == 1 and "Order API, Store, CI |" in out
    assert "Not applicable for 3 components: Order API, Store, CI." in out
    # A single not-applicable component keeps its own row.
    block["results"] = block["results"][:-2]
    out = compose._render_appendix_test_cases(
        _mk_ctx(tmp_path, yaml_data={"test_case_results": block, "components": names}), None, {}
    )
    assert "| [TC-AUTHZ-04](#tc-authz-04) · Order API | AuthZ | Not applicable |" in out


@pytest.mark.parametrize(
    ("confirmed", "reason"),
    [
        ((True, True), "control evidenced at all 2 candidate locations"),
        ((False, False), "control evidenced by model review only at all 2 candidate locations"),
        ((True, False), "control evidenced at all 2 candidate locations, by model review only at 1 of them"),
    ],
)
def test_a_reason_names_controls_that_only_model_review_supports(catalog, confirmed, reason):
    controls = [_cand("control", confirmed=value) for value in confirmed]
    assert _outcome(catalog, controls)["reason"] == reason
    finding = _outcome(catalog, [_cand("weakness"), *controls])["reason"]
    assert finding.startswith("weakness at 1 of 3 candidate locations; control evidenced")
    assert ("model review only" in finding) is (not all(confirmed))


def test_test_case_findings_are_listed_apart_and_their_model_text_stays_text(catalog, tmp_path):
    from renderers import compose_threat_model as compose

    from tests.test_compose_threat_model_cov import _mk_ctx

    findings = _pilot(catalog, tmp_path)["findings"]
    model = {"test_case_findings": findings, "components": [{"id": "api", "name": "Order API"}]}
    out = compose._render_test_case_findings(_mk_ctx(tmp_path, yaml_data=model), None, {})
    assert out.startswith('<a id="verification-findings"></a>\n## Verification Findings')
    assert "do not count in the totals of the findings register" in out
    row = next(line for line in out.splitlines() if line.startswith("| TCF-001 |"))
    assert "[TC-AUTHZ-01](#tc-authz-01)" in row and "Order API" in row and "server.js:8" in row
    # Model-written text cannot add a link or a table column.
    assert "Order \\[access\\](javascript:alert(1)) \\| lacks" in row and row.count(" | ") == 5
    assert compose._render_test_case_findings(_mk_ctx(tmp_path, yaml_data={}), None, {}) == ""


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
        # Nothing was examined, so nothing was settled.
        ([], 0, "undecidable", "model", "examined no candidate location"),
    ],
)
def test_component_outcome_table(catalog, candidates, unexamined, outcome, basis, reason):
    row = _outcome(catalog, candidates, unexamined=unexamined)
    assert (row["outcome"], row["evidence_basis"]) == (outcome, basis)
    assert reason in row["reason"]
    assert row["candidates"]["applicable"] == sum(c["status"] != "rejected" for c in candidates) + unexamined
    assert row["candidates"]["unexamined"] == unexamined
    assert list(_block_validator().iter_errors({"catalog_version": "1", "results": [row]})) == []


@pytest.mark.parametrize("goal", [case["id"] for case in tcr.load_catalog()["test_cases"] if case.get("goal")])
def test_a_goal_examined_without_a_finding_records_no_finding_and_never_a_control(catalog, goal):
    # A goal test case has no starting candidates; its search covers the component, not single locations.
    case = _case(catalog, goal)
    row = tcr.component_outcome(case, "api", [], proposed_outcome="no_finding")
    assert (row["outcome"], row["reason"], row["evidence_basis"]) == ("no_finding", tcr.GOAL_NO_FINDING_REASON, "model")
    assert "proposed_outcome" not in row
    for proposed in (None, "undecidable", "control", "partial"):
        assert tcr.component_outcome(case, "api", [], proposed_outcome=proposed)["outcome"] == "undecidable"
    # A concrete test case without an examined location stays undecidable, whatever the model proposed.
    assert _outcome(catalog, [], proposed_outcome="no_finding")["outcome"] == "undecidable"
    # A replaced job overrides the goal's answer.
    assert tcr.replacement_result(case, "api", "failure")["outcome"] == "undecidable"


def test_a_weakness_whose_finding_was_dropped_is_undecidable_with_the_fixed_reason(catalog):
    case = _case(catalog, "TC-AUTHZ-01")
    dropped = {
        "candidate_id": "m-1",
        "origin": "model",
        "anchor": {"repository_id": "repo-" + "1" * 16, "file": "server.js", "line": 9},
        "status": "undecidable",
        "undecidable_reason": "finding-dropped",
        "evidence": [],
        "finding_ids": [],
    }
    records, _ = tcr.assess_candidates(case, {"candidates": [dropped]}, [])
    row = tcr.component_outcome(case, "api", records)
    assert row["outcome"] == "undecidable" and tcr.UNDECIDABLE_REASONS["finding-dropped"] in row["reason"]


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


def test_a_location_without_a_route_runs_only_the_site_check(catalog):
    from model.case_postchecks import SITE_LINE

    facts = {**_FACTS, "sites": {"raw_query": [["server.js", 20]]}}
    location = [{"candidate_id": PC1, "origin": "pre-check", "anchor": {"file": "server.js", "line": 20}}]
    weakness = {"status": "weakness", "evidence": [_EVIDENCE], "finding_ids": []}
    answer = {
        "test_case_id": "TC-INPUT-01",
        "proposed_outcome": "finding",
        "reason": "text",
        "candidates": [{"candidate_id": PC1, "origin": "pre-check", **weakness}],
    }
    records, checks = tcr.assess_candidates(_case(catalog, "TC-INPUT-01"), answer, location, facts)
    assert checks == [
        {
            "candidate_id": PC1,
            "check": "site-reached",
            "site": "raw_query",
            "claim": "weakness",
            "result": "confirmed",
            "reason": SITE_LINE,
        }
    ]
    assert records[0]["confirmed"]
    # The route checks of an owner test case still need a route.
    owner = {**answer, "test_case_id": "TC-AUTHZ-01"}
    assert tcr.assess_candidates(_case(catalog, "TC-AUTHZ-01"), owner, location, facts)[1] == []


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


def test_candidates_of_a_replaced_job_are_undecidable_and_the_answered_ones_keep_their_outcome(catalog):
    # The job holding PC3 failed; the other job answered PC1.
    answer = _answer({"status": "weakness"}, {"status": "neither"}, ["api-001"])
    answer["candidates"] = answer["candidates"][:1]
    reply = {
        "test_cases": [answer],
        "findings": [{"local_id": "api-001", "test_case_ids": ["TC-AUTHZ-01"], "candidate_ids": [PC1]}],
    }
    precheck = {"TC-AUTHZ-01": _PRECHECK}
    (row,) = tcr.investigation_results(reply, "api", precheck=precheck, facts=_FACTS, replaced={PC3: "failure"})[
        "results"
    ]
    assert (row["outcome"], row["finding_ids"]) == ("finding", ["api-001"])
    assert {key: row["candidates"][key] for key in ("applicable", "undecidable", "unexamined")} == {
        "applicable": 2,
        "undecidable": 1,
        "unexamined": 0,
    }
    # Without a weakness, the replaced candidate leaves the test case undecidable for its job's cause.
    answer["candidates"][0].update(status="neither", finding_ids=[])
    (row,) = tcr.investigation_results(
        {"test_cases": [answer], "findings": []}, "api", precheck=precheck, facts=_FACTS, replaced={PC3: "budget"}
    )["results"]
    assert row["outcome"] == "undecidable"
    assert row["reason"] == f"1 of 2 candidate locations undecidable: {tcr.REPLACEMENT_REASONS['budget']}"
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


# --- survey and verification combined (REQ-040) -------------------------------------


def _survey(threat_id, cwe, file, line, *instances, source="stride"):
    return {
        "id": threat_id,
        "source": source,
        "cwe": cwe,
        "evidence": [{"file": file, "line": line}],
        "instances": [{"file": f, "line": n} for f, n in instances],
    }


def _verified(finding_id, cwe, file, line, case="TC-AUTHZ-01"):
    return {"id": finding_id, "cwe": cwe, "evidence": {"file": file, "line": line}, "test_case_ids": [case]}


def test_a_verification_finding_at_a_survey_location_with_the_same_weakness_is_shown_once(catalog):
    threats = [
        _survey("T-001", "CWE-639", "routes/basket.ts", 19, ("server.ts", 426)),
        _survey("T-002", "CWE-79", "routes/basket.ts", 20),
        _survey("T-003", "CWE-639", "routes/order.ts", 35, source="source-scan"),
        _survey("T-004", "CWE-95", "routes/profile.ts", 61),
    ]
    findings = [
        _verified("TCF-001", "CWE-639", "routes/basket.ts", 19),
        _verified("TCF-002", "CWE-639", "server.ts", 426, case="TC-AUTHZ-02"),
        # Another CWE of the same family at the same line is the same weakness.
        _verified("TCF-003", "CWE-862", "routes/basket.ts", 19, case="TC-AUTHZ-02"),
        _verified("TCF-004", "CWE-94", "routes/profile.ts", 61, case="TC-INPUT-03"),
        # A neighbouring line, another family at the same line, and a scanner finding stay apart.
        _verified("TCF-005", "CWE-639", "routes/basket.ts", 20),
        _verified("TCF-006", "CWE-943", "routes/basket.ts", 19, case="TC-INPUT-02"),
        _verified("TCF-007", "CWE-639", "routes/order.ts", 35),
    ]
    assert tcr.combine_methods(threats, findings, [], catalog) == {"linked": 4, "contradicted": 0}
    assert threats[0]["verification"] == {
        "finding_ids": ["TCF-001", "TCF-002", "TCF-003"],
        "test_case_ids": ["TC-AUTHZ-01", "TC-AUTHZ-02"],
    }
    assert threats[0]["test_case_ids"] == ["TC-AUTHZ-01", "TC-AUTHZ-02"]
    assert [row.get("survey_finding_ids") for row in findings] == [
        ["T-001"],
        ["T-001"],
        ["T-001"],
        ["T-004"],
        None,
        None,
        None,
    ]
    assert "verification" not in threats[1] and "verification" not in threats[2]


def test_unclassified_cwes_link_only_when_they_are_identical(catalog):
    threats = [_survey("T-001", "CWE-359", "routes/memory.ts", 24)]
    findings = [
        _verified("TCF-001", "CWE-200", "routes/memory.ts", 24, case="TC-DATA-01"),
        _verified("TCF-002", "CWE-359", "routes/memory.ts", 24, case="TC-DATA-01"),
        # Neither a verification nor a survey finding without a CWE matches anything.
        _verified("TCF-003", None, "routes/memory.ts", 24, case="TC-DATA-01"),
    ]
    assert tcr.combine_methods(threats, findings, [], catalog) == {"linked": 1, "contradicted": 0}
    assert [row.get("survey_finding_ids") for row in findings] == [None, ["T-001"], None]
    assert tcr.combine_methods(
        [_survey("T-002", None, "a.ts", 1)], [_verified("TCF-004", None, "a.ts", 1)], [], catalog
    ) == {
        "linked": 0,
        "contradicted": 0,
    }


def test_a_control_verified_at_a_survey_location_contradicts_the_finding_but_keeps_it(catalog):
    threats = [
        _survey("T-001", "CWE-639", "routes/payment.ts", 30),
        _survey("T-002", "CWE-79", "routes/payment.ts", 30),
        _survey("T-003", "CWE-639", "routes/wallet.ts", 12),
        _survey("T-004", "CWE-862", "routes/payment.ts", 30),
        _survey("T-005", "CWE-639", "routes/refund.ts", 40),
    ]
    results = [
        {"test_case_id": "TC-AUTHZ-01", "control_locations": [{"file": "routes/payment.ts", "line": 30}]},
        {"test_case_id": "TC-AUTHZ-01", "control_locations": [{"file": "routes/wallet.ts", "line": 12}]},
        # A control on a neighbouring line belongs to another statement and contradicts nothing.
        {"test_case_id": "TC-AUTHZ-01", "control_locations": [{"file": "routes/refund.ts", "line": 41}]},
    ]
    # A weakness that verification found at the same place outweighs its control elsewhere.
    findings = [_verified("TCF-001", "CWE-639", "routes/wallet.ts", 12)]
    assert tcr.combine_methods(threats, findings, results, catalog) == {"linked": 1, "contradicted": 1}
    assert threats[0]["verification_contradicted"] == [
        {"test_case_id": "TC-AUTHZ-01", "file": "routes/payment.ts", "line": 30}
    ]
    # Only a CWE of the verification item is contradicted, not another CWE of its family:
    # an ownership check does not show that a role check exists.
    assert all("verification_contradicted" not in threat for threat in threats[1:])


def test_the_consolidation_counts_each_aspect_as_the_report_links_the_methods(catalog):
    from orchestrator import assessment_test_cases

    threats = [
        _survey("T-001", "CWE-639", "routes/basket.ts", 19),
        _survey("T-002", "CWE-639", "routes/payment.ts", 30),
        _survey("T-003", "CWE-862", "routes/wallet.ts", 12),
        # A scanner finding and a survey finding of another aspect count for no AuthZ line.
        _survey("T-004", "CWE-639", "routes/order.ts", 35, source="source-scan"),
        _survey("T-005", "CWE-89", "routes/search.ts", 23),
    ]
    findings = [
        {**_verified("TCF-001", "CWE-639", "routes/basket.ts", 19), "aspect": "AuthZ"},
        {**_verified("TCF-002", "CWE-639", "routes/order.ts", 50), "aspect": "AuthZ"},
        {**_verified("TCF-003", "CWE-89", "routes/search.ts", 23, case="TC-INPUT-01"), "aspect": "InputVal"},
    ]
    results = [{"test_case_id": "TC-AUTHZ-01", "control_locations": [{"file": "routes/payment.ts", "line": 30}]}]
    tcr.combine_methods(threats, findings, results, catalog)
    assert assessment_test_cases.method_lines(threats, findings, ["AuthZ", "DataProt"], catalog) == [
        "AuthZ · Verify 2 findings, 1 not found by the survey · Survey 3 findings, 2 not found by Verify"
        " · 1 contradicted by a verified control",
        "DataProt · Verify 0 findings, 0 not found by the survey · Survey 0 findings, 0 not found by Verify",
    ]


def test_the_survey_line_counts_what_the_evidence_review_kept_per_verified_aspect(catalog):
    from orchestrator import assessment_test_cases

    # Local IDs repeat across components: each component's review decides its own findings.
    documents = [
        {"threats": [{"local_id": "a", "cwe": "CWE-639"}, {"local_id": "b", "cwe": "CWE-200"}, {"local_id": "c"}]},
        {"threats": [{"local_id": "a", "cwe": "CWE-862"}, {"local_id": "b", "cwe": "CWE-639"}]},
    ]
    reviews = [
        {"decisions": [{"local_id": "a", "verdict": "verified"}, {"local_id": "b", "verdict": "ambiguous"}]},
        {"decisions": [{"local_id": "a", "verdict": "verified"}, {"local_id": "b", "verdict": "refuted"}]},
    ]
    reviews[0]["decisions"].append({"local_id": "c", "verdict": "verified"})
    line = assessment_test_cases.survey_line(documents, reviews, ["AuthZ", "DataProt"], catalog, 7.274)
    assert (
        line
        == "Survey done · 4 findings and 1 refuted by the evidence review · by aspect AuthZ 2, DataProt 1 · ≈ USD 7.27"
    )
    # Without refuted findings or monetary accounting the line names neither.
    line = assessment_test_cases.survey_line(documents[:1], reviews[:1], ["AuthZ"], catalog, None)
    assert line == "Survey done · 3 findings · by aspect AuthZ 1"


def test_investigation_results_name_the_locations_of_evidenced_controls(catalog):
    control = {"status": "control", "control_kind": "code"}
    reply = {"test_cases": [_answer(control, control)], "findings": []}
    result = tcr.investigation_results(reply, "api", precheck={"TC-AUTHZ-01": _PRECHECK}, facts=_FACTS, catalog=catalog)
    # The first control was contradicted by its post-check, so only the confirmed one names its location.
    assert result["results"][0]["control_locations"] == [{"file": "server.js", "line": 12}]


def test_control_locations_stay_valid_when_the_combined_model_qualifies_them(catalog):
    """A verified control stopped every combined run: qualification added fields the schema refused."""
    from orchestrator.assessment_workspace import _qualify

    class Names:
        def split(self, file):
            return "repo-" + "1" * 16, file

        def sha256(self, repository_id, path):
            return "a" * 64

    control = {"status": "control", "control_kind": "code"}
    reply = {"test_cases": [_answer(control, control)], "findings": []}
    block = {
        "catalog_version": "1",
        "results": tcr.investigation_results(
            reply, "api", precheck={"TC-AUTHZ-01": _PRECHECK}, facts=_FACTS, catalog=catalog
        )["results"],
    }
    validator = _block_validator()
    assert list(validator.iter_errors(block)) == []
    qualified = _qualify(block, Names())
    (spot,) = qualified["results"][0]["control_locations"]
    assert spot == {"file": "server.js", "line": 12, "repository_id": "repo-" + "1" * 16, "sha256": "a" * 64}
    assert list(validator.iter_errors(qualified)) == []
    spot["extra"] = "field"
    assert list(validator.iter_errors(qualified))


def test_build_block_keeps_the_aspects_the_budget_left_incomplete(tmp_path):
    (tmp_path / tcr.PILOT_SIDECAR).write_text(json.dumps({"results": [], "incomplete_aspects": ["AuthZ"]}))
    assert tcr.build_block(tmp_path, [])["incomplete_aspects"] == ["AuthZ"]
    (tmp_path / tcr.PILOT_SIDECAR).write_text(json.dumps({"results": [], "incomplete_aspects": []}))
    assert "incomplete_aspects" not in tcr.build_block(tmp_path, [])


def test_the_report_names_both_methods_a_contradiction_and_an_incomplete_aspect(catalog, tmp_path):
    from renderers import compose_threat_model as compose

    from tests.test_compose_threat_model_cov import _mk_ctx

    both = {"verification": {"finding_ids": ["TCF-001"], "test_case_ids": ["TC-AUTHZ-01"]}}
    assert compose._verification_card(both) == (
        "**Found by:** survey and verification (TCF-001; [TC-AUTHZ-01](#tc-authz-01))"
    )
    disputed = {"verification_contradicted": [{"test_case_id": "TC-AUTHZ-01", "file": "routes/a.ts", "line": 3}]}
    assert compose._verification_card(disputed).startswith(
        "**Contradicted by verification:** a control was evidenced at [TC-AUTHZ-01](#tc-authz-01) at routes/a.ts:3."
    )
    assert compose._verification_card({}) == ""
    findings = [
        {**_verified("TCF-001", "CWE-639", "a.ts", 1), "survey_finding_ids": ["T-001"], "title": "x", "risk": "High"},
        {**_verified("TCF-002", "CWE-639", "b.ts", 1), "title": "Only verification", "risk": "High"},
    ]
    out = compose._render_test_case_findings(_mk_ctx(tmp_path, yaml_data={"test_case_findings": findings}), None, {})
    assert "| TCF-002 |" in out and "| TCF-001 |" not in out
    assert "1 further verification finding matched a survey finding" in out
    block = {"catalog_version": "1", "results": [], "incomplete_aspects": ["AuthZ"]}
    appendix = compose._render_appendix_test_cases(_mk_ctx(tmp_path, yaml_data={"test_case_results": block}), None, {})
    assert "Verification of AuthZ is incomplete: the model budget ended before every job ran" in appendix
