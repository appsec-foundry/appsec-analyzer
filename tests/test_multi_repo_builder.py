"""The canonical assembler preserves scoped evidence and existing policy gates."""

import copy
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from contexts.multi_repo_analysis import contract
from model.build_threat_model_yaml import build_assessment_model
from model.merge_threats import merge_assessment
from shared.assessment_sources import presentation_model
from validators.validate_intermediate import validate_threat_model_output

from tests.test_multi_repo_analysis import stride
from tests.test_multi_repo_boundaries import crossing_input

ROOT = Path(__file__).resolve().parents[1]


def inputs(tmp_path, *, names=("edge", "service")):
    scope, components, receipt, flows, _ = crossing_input(tmp_path, names=names)
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    documents, reviews = [], []
    for component, evidence in zip(components["components"], flows["data_flows"][0]["evidence"], strict=True):
        document = stride(component, evidence, identity)
        document["threats"][0]["cwe"] = "CWE-20"
        documents.append(document)
        reviews.append(
            dict(
                **identity,
                decisions=[
                    dict(
                        local_id="issue-1",
                        verdict="verified",
                        reason="Source confirms the practice.",
                        evidence=[evidence],
                    )
                ],
            )
        )
    merged = merge_assessment(scope, components, documents, reviews, boundaries=[])
    return scope, dict(
        skill_cfg=dict(
            assessment_scope="multiple-repositories",
            source_scope_sha256=components["source_scope_sha256"],
            mode="full",
            stride_model="test",
            invocation_args="--repo /private/root --token hidden",
        ),
        architecture=dict(components=components, finalization=receipt, data_flows=flows, assets=[]),
        controls=[],
        boundaries=dict(schema_version=3, source_scope_sha256=components["source_scope_sha256"], trust_boundaries=[]),
        merged=merged,
        plugin_root=ROOT,
        project="Combined system",
    )


def test_cited_catalog_requirements_reach_the_merged_and_combined_model(tmp_path, monkeypatch):
    real = stride

    def citing(component, evidence, identity):
        document = real(component, evidence, identity)
        document["threats"][0]["violated_requirements"] = ["SEC-AUTH-1"]
        return document

    monkeypatch.setitem(globals(), "stride", citing)
    scope, kwargs = inputs(tmp_path)
    cited = [t.get("violated_requirements") for t in kwargs["merged"]["threats"]]
    assert cited == [["SEC-AUTH-1"], ["SEC-AUTH-1"]]
    with pytest.raises(ValueError, match="outside the captured catalog"):
        build_assessment_model(scope, **kwargs)
    with pytest.raises(ValueError, match="outside the captured catalog"):
        build_assessment_model(scope, **kwargs, context={"requirements": {"ids": ["SEC-LOG-2"]}})
    document, _ = build_assessment_model(scope, **kwargs, context={"requirements": {"ids": ["SEC-AUTH-1"]}})
    assert [t.get("violated_requirements") for t in document["threats"]] == [["SEC-AUTH-1"], ["SEC-AUTH-1"]]
    assert document["meta"]["check_requirements"] is True


@pytest.mark.parametrize("names", [("edge", "service"), ("gateway", "processor")])
def test_assembler_preserves_all_roots_and_qualified_nested_findings(tmp_path, names):
    scope, kwargs = inputs(tmp_path, names=names)
    original = copy.deepcopy(kwargs)
    document, _ = build_assessment_model(scope, **kwargs)
    assert kwargs == original
    assert validate_threat_model_output(document)[0]
    assert document["meta"]["schema_version"] == 2
    assert "git" not in document["meta"] and "repo_url" not in document["meta"]
    assert "invocation" not in document["meta"] and "enrichment_pass" not in document["meta"]
    assert document["source_inventory"] == scope.inventory()
    assert len(document["threats"]) == len(document["components"]) == 2
    anchors = [t["evidence"][0] for t in document["threats"]]
    assert len({e["repository_id"] for e in anchors}) == 2
    assert {e["file"] for e in anchors} == {"app.py"}
    assert document["abuse_case_analysis"]["status"] == "not_run"
    assert document["business_context_trace"]["status"] == "not_configured"
    assert document["mitigations"]
    for component in document["components"]:
        assert component["threat_ids"] == [t["id"] for t in document["threats"] if t["component"] == component["id"]]
    view = presentation_model(document)
    assert len({t["evidence"][0]["file"] for t in view["threats"]}) == 2
    assert not scope.output.exists()


@pytest.mark.parametrize(
    "kind", ["scope", "fingerprint", "owner", "hash", "component", "duplicate", "requirements", "business", "project"]
)
def test_assembler_rejects_stale_foreign_or_unrepresented_inputs(tmp_path, kind):
    scope, kwargs = inputs(tmp_path)
    if kind == "scope":
        kwargs["skill_cfg"]["source_scope_sha256"] = "0" * 64
    elif kind == "fingerprint":
        kwargs["merged"]["component_inventory_fingerprint"] = "sha256:" + "0" * 64
    elif kind == "owner":
        kwargs["merged"]["threats"][0]["evidence"]["repository_id"] = kwargs["merged"]["threats"][1]["evidence"][
            "repository_id"
        ]
    elif kind == "hash":
        kwargs["merged"]["threats"][0]["evidence"]["sha256"] = "0" * 64
    elif kind == "component":
        kwargs["merged"]["threats"][0]["component_id"] = "foreign-component"
    elif kind == "duplicate":
        kwargs["merged"]["threats"][1]["t_id"] = kwargs["merged"]["threats"][0]["t_id"]
    elif kind == "requirements":
        kwargs["skill_cfg"]["check_requirements"] = True
    elif kind == "business":
        kwargs["skill_cfg"]["business_context_source"] = "configured-context"
    else:
        kwargs["project"] = "Forged\nreport"
    with pytest.raises(ValueError):
        build_assessment_model(scope, **kwargs)
    assert not scope.output.exists()


def test_refuted_findings_never_reenter_through_the_weakness_register(tmp_path):
    scope, kwargs = inputs(tmp_path)
    refuted = kwargs["merged"]["threats"][0]
    refuted["evidence_check"] = "refuted"
    refuted["evidence_basis"] = "refuted"
    refuted["evidence_check_reason"] = "The implementation contradicts this claim."
    document, _ = build_assessment_model(scope, **kwargs)
    assert refuted["t_id"] not in {t["id"] for t in document["threats"]}
    for weakness in document.get("weaknesses", []):
        assert refuted["t_id"] not in str(weakness)


def test_explicit_skips_remain_distinct_from_missing_context(tmp_path):
    scope, kwargs = inputs(tmp_path)
    kwargs["skill_cfg"].update(
        skip_business_context=True, skip_abuse_case_verification=True, business_context_source="ignored-by-request"
    )
    document, _ = build_assessment_model(scope, **kwargs)
    assert document["business_context_trace"]["status"] == "skipped"
    assert document["abuse_case_analysis"]["status"] == "skipped"


def _duplicated(tmp_path, other_verdict, names=("edge", "service")):
    scope, components, receipt, flows, _ = crossing_input(tmp_path, names=names)
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    documents, reviews = [], []
    for component, evidence in zip(components["components"], flows["data_flows"][0]["evidence"], strict=True):
        document = stride(component, evidence, identity)
        # Same location and mechanism, reported again with a higher rating.
        duplicate = dict(copy.deepcopy(document["threats"][0]), local_id="issue-2")
        duplicate.update(likelihood="High", impact="Critical", risk="Critical")
        document["threats"].append(duplicate)
        next(row for row in document["coverage"] if row["category"] == "Tampering")["finding_ids"].append("issue-2")
        documents.append(document)
        verdicts = {"issue-1": "verified", "issue-2": other_verdict}
        reviews.append(
            dict(
                **identity,
                decisions=[
                    dict(local_id=key, verdict=value, reason="Source review decision.", evidence=[evidence])
                    for key, value in verdicts.items()
                ],
            )
        )
    return merge_assessment(scope, components, documents, reviews, boundaries=[])


def _reviewed_in_parts(tmp_path, findings, names=("edge", "service"), verdict="verified"):
    """Each component holds `findings` findings, all decided by one joined multi-job review."""
    scope, components, receipt, flows, _ = crossing_input(tmp_path, names=names)
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    documents, reviews = [], []
    for component, evidence in zip(components["components"], flows["data_flows"][0]["evidence"], strict=True):
        document = stride(component, evidence, identity)
        first = document["threats"][0]
        document["threats"] = [dict(copy.deepcopy(first), local_id=f"issue-{n}") for n in range(1, findings + 1)]
        tampering = next(row for row in document["coverage"] if row["category"] == first["stride"])
        tampering["finding_ids"] = [t["local_id"] for t in document["threats"]]
        documents.append(document)
        reviews.append(
            dict(
                **identity,
                decisions=[
                    dict(local_id=t["local_id"], verdict=verdict, reason="Source review decision.", evidence=[evidence])
                    for t in document["threats"]
                ],
            )
        )
    return merge_assessment(scope, components, documents, reviews, boundaries=[])


@pytest.mark.parametrize("findings", [101, 160])
@pytest.mark.parametrize("names", [("edge", "service"), ("gateway", "processor")])
def test_a_component_reviewed_in_several_jobs_keeps_every_paid_decision(tmp_path, findings, names):
    """One review job decides at most its own limit; the joined review of a component may hold more."""
    per_job = contract("multi-repo-evidence-review.schema.json")["properties"]["decisions"]["maxItems"]
    assert findings > per_job
    merged = _reviewed_in_parts(tmp_path, findings, names)
    assert merged["threats"]


def test_a_joined_review_still_rejects_an_invalid_decision(tmp_path):
    with pytest.raises(ValueError, match="invalid evidence review"):
        _reviewed_in_parts(tmp_path, 101, verdict="plausible")


@pytest.mark.parametrize("other_verdict", ["refuted", "ambiguous"])
@pytest.mark.parametrize("names", [("edge", "service"), ("gateway", "processor")])
def test_differently_reviewed_duplicate_cannot_absorb_a_verified_finding(tmp_path, other_verdict, names):
    merged = _duplicated(tmp_path, other_verdict, names)
    verified = [t for t in merged["threats"] if t["evidence_check"] == "verified"]
    assert len(verified) == 2
    assert {t["evidence"]["repository_id"] for t in verified} == {
        t["evidence"]["repository_id"] for t in merged["threats"]
    }


def test_equally_reviewed_duplicates_still_merge(tmp_path):
    merged = _duplicated(tmp_path, "verified")
    assert len(merged["threats"]) == 2
    assert all(t["evidence_check"] == "verified" for t in merged["threats"])


@pytest.mark.parametrize("names", [("edge", "service"), ("gateway", "processor")])
def test_a_merge_candidate_spanning_repositories_never_reaches_the_merger(tmp_path, names):
    from model.merge_threats import _group_candidates

    scope, components, receipt, flows, _ = crossing_input(tmp_path, names=names)
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    documents, reviews = [], []
    for component, evidence in zip(components["components"], flows["data_flows"][0]["evidence"], strict=True):
        document = stride(component, evidence, identity)
        document["threats"][0]["cwe"] = "CWE-20"
        documents.append(document)
        decision = dict(local_id="issue-1", verdict="verified", reason="Source confirms it.", evidence=[evidence])
        reviews.append(dict(**identity, decisions=[decision]))
    offered = []
    merged = merge_assessment(
        scope,
        components,
        documents,
        reviews,
        boundaries=[],
        review_groups=lambda verdict, groups: offered.append((verdict, groups)) or [],
    )
    # The two findings form a candidate group, but one per repository.
    assert _group_candidates(copy.deepcopy(merged["threats"]))
    assert offered == []
    assert len(merged["threats"]) == 2


def test_stride_finding_without_cwe_is_rejected_at_its_contract(tmp_path):
    from contexts.multi_repo_analysis import contract
    from jsonschema import Draft202012Validator

    scope, components, receipt, flows, _ = crossing_input(tmp_path)
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    component, evidence = components["components"][0], flows["data_flows"][0]["evidence"][0]
    document = stride(component, evidence, identity)
    validator = Draft202012Validator(contract("multi-repo-stride.schema.json"))
    assert validator.is_valid(document)
    for value in (None, "missing"):
        broken = copy.deepcopy(document)
        if value is None:
            broken["threats"][0]["cwe"] = None
        else:
            del broken["threats"][0]["cwe"]
        assert not validator.is_valid(broken)


def _linked(tmp_path, owner_index):
    """A verified authorization finding at the line an internal boundary cites.

    Both roots hold an `app.py` with the same line, so a match on the bare file
    name would also link the other root's finding. The CWE carries no sink class,
    so the link depends only on the cited root and line.
    """
    scope, components, receipt, flows, _ = crossing_input(tmp_path)
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    evidences = flows["data_flows"][0]["evidence"]
    documents, reviews = [], []
    for component, evidence in zip(components["components"], evidences, strict=True):
        document = stride(component, evidence, identity)
        document["threats"][0]["cwe"] = "CWE-862"
        documents.append(document)
        reviews.append(
            dict(
                **identity,
                decisions=[dict(local_id="issue-1", verdict="verified", reason="Raw query.", evidence=[evidence])],
            )
        )
    ids = [row["id"] for row in components["components"]]
    boundary = dict(
        id="tb-1",
        name="Service to store",
        to=ids[1 - owner_index],
        kind="process",
        assumption="Queries bind every value.",
        evidence=[copy.deepcopy(evidences[owner_index])],
        confidence="confirmed",
        resolution_status="resolved",
        sources=["detected"],
        **{"from": ids[owner_index]},
    )
    return merge_assessment(scope, components, documents, reviews, boundaries=[boundary]), ids


@pytest.mark.parametrize("owner_index", [0, 1])
def test_qualified_merge_links_only_the_root_whose_line_the_boundary_cites(tmp_path, owner_index):
    merged, ids = _linked(tmp_path, owner_index)
    linked = {
        threat["component_id"]: [ref["boundary_id"] for ref in threat.get("boundary_refs") or []]
        for threat in merged["threats"]
    }
    assert linked[ids[owner_index]] == ["tb-1"]
    assert linked[ids[1 - owner_index]] == []


def _verification(tmp_path, *changes, verdicts=("verified", "verified"), scanner=False, combine_texts=None):
    """One survey finding per component and verification findings of the first component at its location.

    Each of ``changes`` edits one verification finding; ``scanner`` makes the first component's finding a
    scanner finding instead of a survey finding.
    """
    from model.finding_intake import apply_intake

    # A second line, so that a neighbouring line holds code.
    text = "return_value = validate_request(payload)\nreturn_value = validate_request(other)\n"
    scope, components, receipt, flows, _ = crossing_input(
        tmp_path, files={name: {"app.py": text} for name in ("edge", "service")}
    )
    identity = dict(
        schema_version=2,
        source_scope_sha256=components["source_scope_sha256"],
        component_inventory_fingerprint=receipt["component_inventory_fingerprint"],
    )
    documents, reviews, scanned = [], [], {}
    for component, evidence, verdict in zip(
        components["components"], flows["data_flows"][0]["evidence"], verdicts, strict=True
    ):
        document = stride(component, evidence, identity)
        local_id = "issue-1"
        if scanner and not documents:
            row = dict(document["threats"].pop(), local_id="deterministic-scan-001", source="source-scan")
            row.update(source_check_id="INJ-001", architectural_violation=False)
            apply_intake(row, dispatch_component=component["id"], component_name=component["name"])
            scanned[component["id"]] = [row]
            for coverage in document["coverage"]:
                coverage.update(disposition="no-evidence", finding_ids=[])
            local_id = row["local_id"]
        documents.append(document)
        decision = dict(local_id=local_id, verdict=verdict, reason="Source review decision.", evidence=[evidence])
        reviews.append(dict(**identity, decisions=[decision]))
    first = components["components"][0]
    survey = copy.deepcopy(stride(first, flows["data_flows"][0]["evidence"][0], identity)["threats"][0])
    findings = []
    for number, change in enumerate(changes, 1):
        finding = {key: value for key, value in copy.deepcopy(survey).items() if key != "local_id"}
        finding.update(
            id=f"TCF-{number:03d}",
            component_id=first["id"],
            aspect="InputVal",
            test_case_ids=["TC-INPUT-01"],
            title="Verification: request handler accepts unvalidated input",
            remediation=dict(
                effort="Low",
                steps=["Validate the input against the accepted data type.", "Log each rejected request."],
                verification="Submit malformed input and assert that the endpoint rejects it.",
            ),
            route_ids=[],
            post_check_confirmed=False,
        )
        change(finding)
        findings.append(finding)
    merged = merge_assessment(
        scope,
        components,
        documents,
        reviews,
        boundaries=[],
        scanner_threats=scanned,
        verification_threats={first["id"]: findings},
        combine_texts=combine_texts,
    )
    return merged, first["id"]


def _held(merged, finding_id):
    (threat,) = [t for t in merged["threats"] if finding_id in (t.get("verification") or {}).get("finding_ids", [])]
    return threat


@pytest.mark.parametrize("category", ["TH-01", "TH-02"])
def test_a_verification_finding_on_a_survey_line_becomes_part_of_it(tmp_path, category):
    """REQ-040: same line and CWE family make one finding, whatever category each method assigned."""
    merged, first = _verification(tmp_path, lambda f: f.update(threat_category_id=category))
    assert len(merged["threats"]) == 2
    threat = _held(merged, "TCF-001")
    assert threat["component_id"] == first and threat["found_by"] == ["survey", "verification"]
    assert threat["verification"] == {"finding_ids": ["TCF-001"], "test_case_ids": ["TC-INPUT-01"]}
    assert threat["test_case_ids"] == ["TC-INPUT-01"]
    # Equal risk keeps the reviewed finding's text and verdict; the steps of both parts are listed once each.
    assert threat["title"] == "Unvalidated input reaches the request handler"
    assert (threat["evidence_check"], threat["evidence_basis"]) == ("verified", "llm-verified")
    assert threat["remediation"]["steps"] == [
        "Validate the input against the accepted data type.",
        "Reject requests that fail validation.",
        "Log each rejected request.",
    ]
    assert [i["source_ref"] for i in threat["instances"]] == ["issue-1", "TCF-001"]
    (other,) = [t for t in merged["threats"] if t is not threat]
    assert other["found_by"] == ["survey"] and "verification" not in other


def test_a_riskier_verification_finding_stays_with_the_reviewed_verdict(tmp_path):
    merged, _ = _verification(tmp_path, lambda f: f.update(likelihood="High", impact="High", risk="High"))
    threat = _held(merged, "TCF-001")
    assert threat["title"].startswith("Verification:") and threat["risk"] == "High"
    assert (threat["evidence_check"], threat["evidence_basis"]) == ("verified", "llm-verified")
    assert threat["found_by"] == ["survey", "verification"]
    assert {i["source_ref"] for i in threat["instances"]} == {"issue-1", "TCF-001"}


def test_a_verification_finding_on_a_scanner_line_names_the_scanner_rule(tmp_path):
    merged, _ = _verification(tmp_path, lambda f: None, scanner=True)
    assert len(merged["threats"]) == 2
    threat = _held(merged, "TCF-001")
    assert threat["found_by"] == ["scanners", "verification"]
    assert any(i.get("source_check_id") == "INJ-001" for i in threat["instances"])


@pytest.mark.parametrize(
    "change",
    [
        lambda f: f["evidence"].update(line=f["evidence"]["line"] + 1),
        lambda f: f.update(cwe="CWE-798"),
    ],
    ids=["neighbouring line", "other family"],
)
@pytest.mark.parametrize("confirmed", [False, True])
def test_a_verification_finding_elsewhere_stays_a_finding_of_its_own(tmp_path, change, confirmed):
    """REQ-040: without a reviewed partner, a post-check scores it; model review alone leaves it unscored."""
    merged, first = _verification(tmp_path, lambda f: (change(f), f.update(post_check_confirmed=confirmed)))
    assert len(merged["threats"]) == 3
    threat = _held(merged, "TCF-001")
    assert threat["found_by"] == ["verification"] and threat["component_id"] == first
    assert "post_check_confirmed" not in threat and "aspect" not in threat
    if confirmed:
        assert (threat["evidence_check"], threat["evidence_basis"]) == ("verified", "pointer-resolved")
    else:
        assert threat["evidence_check"] == "ambiguous" and threat["evidence_tier"] == "insecure-practice"
        assert "cvss_v4" not in threat


def test_a_refuted_finding_never_absorbs_a_verification_finding(tmp_path):
    merged, _ = _verification(tmp_path, lambda f: None, verdicts=("refuted", "verified"))
    assert len(merged["threats"]) == 3
    threat = _held(merged, "TCF-001")
    assert threat["found_by"] == ["verification"] and threat["evidence_check"] == "ambiguous"
    (refuted,) = [t for t in merged["threats"] if t["evidence_check"] == "refuted"]
    assert refuted["found_by"] == ["survey"] and "verification" not in refuted


def test_verification_findings_about_different_routes_on_one_line_stay_apart(tmp_path):
    """REQ-040: one line can register several routes; the second route's finding is no repeat."""
    merged, _ = _verification(
        tmp_path, lambda f: f.update(route_ids=["route-1"]), lambda f: f.update(route_ids=["route-2"])
    )
    assert len(merged["threats"]) == 3
    joined, alone = _held(merged, "TCF-001"), _held(merged, "TCF-002")
    assert joined["found_by"] == ["survey", "verification"] and alone is not joined
    assert alone["found_by"] == ["verification"]
    # The routes only kept them apart; the merged findings do not carry them.
    assert all("route_ids" not in t for t in merged["threats"])


def test_verification_findings_must_belong_to_their_component(tmp_path):
    with pytest.raises(ValueError, match="verification finding under another component"):
        _verification(tmp_path, lambda f: f.update(component_id="foreign-component"))


def _rewrite(scenario):
    """A combiner that rewrites every requested finding with ``scenario(request)``."""
    requests = []

    def combine(batch):
        requests.extend(batch)
        return [
            {
                "key": request["key"],
                "title": "Combined: request handler accepts unvalidated input",
                "scenario": scenario(request),
                "remediation": {
                    "steps": ["Validate the input against the accepted data type.", "Log each rejected request."],
                    "verification": "Submit malformed input and assert a rejection and a log entry.",
                },
            }
            for request in batch
        ]

    return combine, requests


def test_a_finding_of_several_methods_gets_a_text_written_from_its_parts_only(tmp_path):
    """REQ-040: the model writes title, scenario and remediation; the code keeps every other field."""
    combine, requests = _rewrite(lambda r: "An attacker sends malformed input to " + " and ".join(r["locations"]) + ".")
    merged, _ = _verification(tmp_path, lambda f: None, combine_texts=combine)
    threat = _held(merged, "TCF-001")
    (request,) = requests
    # The request names each part's method, location and texts, never a repository ID or source.
    assert request["locations"] == ["app.py:1"] and [p["methods"] for p in request["parts"]] == [
        ["survey"],
        ["verification"],
    ]
    assert {p["location"] for p in request["parts"]} == {"app.py:1"} and "repository_id" not in str(request)
    assert threat["title"] == "Combined: request handler accepts unvalidated input"
    assert threat["scenario"] == "An attacker sends malformed input to app.py:1."
    assert threat["remediation"]["verification"] == "Submit malformed input and assert a rejection and a log entry."
    assert threat["risk"] == "Medium" and threat["found_by"] == ["survey", "verification"]
    assert all("_combination_parts" not in t for t in merged["threats"])


@pytest.mark.parametrize("combine", [None, "uncited", "failed"])
def test_without_a_faithful_rewrite_the_most_severe_part_keeps_its_text(tmp_path, combine):
    """REQ-040: no call, a text that drops a location, or no reply keep the fallback."""
    if combine == "uncited":
        combine, _ = _rewrite(lambda r: "An attacker sends malformed input to the request handler.")
    elif combine == "failed":
        combine = lambda batch: []  # noqa: E731
    merged, _ = _verification(tmp_path, lambda f: f.update(risk="High", impact="High"), combine_texts=combine)
    threat = _held(merged, "TCF-001")
    assert threat["title"].startswith("Verification:") and threat["risk"] == "High"
    assert threat["remediation"]["steps"] == [
        "Validate the input against the accepted data type.",
        "Log each rejected request.",
        "Reject requests that fail validation.",
    ]
    assert all("_combination_parts" not in t for t in merged["threats"])


def test_a_finding_of_one_method_is_never_rewritten(tmp_path):
    combine, requests = _rewrite(lambda r: " ".join(r["locations"]))
    merged, _ = _verification(tmp_path, lambda f: f.update(cwe="CWE-798"), combine_texts=combine)
    assert requests == [] and all(t["found_by"] in (["survey"], ["verification"]) for t in merged["threats"])
