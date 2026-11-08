"""Runtime hypotheses keep controls and admitted sources through export (REQ-049)."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from contexts import multi_repo_analysis as stage
from jsonschema import Draft202012Validator
from model.build_threat_model_yaml import build_assessment_model
from model.merge_threats import _merge_member_metadata
from renderers.render_pentest_tasks import build_document
from runtime.assessment_host import ExchangeError
from shared.assessment_sources import validate_portable_model
from validators.validate_intermediate import validate_pentest_tasks, validate_threat_model_output

from tests.test_multi_repo_analysis import FP, sources, stride
from tests.test_multi_repo_builder import inputs
from tests.test_pentest_tasks import _merged, _stride_threat

ROOT = Path(__file__).resolve().parents[1]


def context(evidence):
    return {
        "version": 1,
        "variants": [
            {
                "id": "search",
                "request": {"method": "GET", "path": "/search", "inputs": [{"location": "query", "name": "q"}]},
                "hypothesis": "A condition in the quoted input changes the selected records",
                "mechanism": {"expression": "SELECT id FROM items WHERE name = '<input>'", "binding": "concatenated"},
                "processing": [
                    {
                        "operation": "filter",
                        "description": "Reject uppercase UNION before decoding",
                        "evidence": [evidence],
                    },
                    {"operation": "decode", "description": "Decode the accepted value", "evidence": [evidence]},
                ],
                "controls": [
                    {
                        "kind": "blacklist",
                        "description": "Case-sensitive keyword match",
                        "status": "observed",
                        "limitation": "Other predicates require a runtime check",
                        "evidence": [evidence],
                    }
                ],
                "prerequisites": ["Operator supplies a known harmless record"],
                "expected_observations": ["The selected id stays stable for the baseline and true condition"],
                "negative_controls": ["Repeat a false condition and compare the selected id, not a reflected input"],
                "unknowns": ["Deployed database driver is unknown"],
                "evidence": [evidence],
                "required_capabilities": ["query"],
            }
        ],
    }


def test_context_survives_assembly_and_pentest_export(tmp_path):
    scope, kwargs = inputs(tmp_path)
    finding = kwargs["merged"]["threats"][0]
    expected = context(copy.deepcopy(finding["evidence"]))
    finding["verification_context"] = expected
    document, _ = build_assessment_model(scope, **kwargs)
    validate_portable_model(document)
    assert validate_threat_model_output(document)[0]
    exported = next(t for t in document["threats"] if t["id"] == finding["t_id"])
    assert exported["verification_context"] == expected
    for dialect in ("generic", "strix"):
        tasks = build_document(
            _merged(_stride_threat(verification_context=exported["verification_context"])),
            dialect,
            "security-assessment.yaml",
            None,
            "fixture",
        )
        task = tasks["tasks"][0]
        assert task["verification_context"] == expected
        assert task["test_strategy"]["variants"][0]["negative_controls"] == expected["variants"][0]["negative_controls"]
        assert validate_pentest_tasks(tasks)[0]
    finding.pop("verification_context")
    older, _ = build_assessment_model(scope, **kwargs)
    assert validate_threat_model_output(older)[0]
    assert "verification_context" not in older["threats"][0]


@pytest.mark.parametrize("mutation", ["outside-job", "unread", "stale", "duplicate"])
def test_context_sources_must_be_served(tmp_path, mutation):
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    artifact["threats"][0]["verification_context"] = context(copy.deepcopy(evidence[0]))
    flows = dict(component_inventory_fingerprint=FP, data_flows=[])
    stage.validate_stride(scope, components[0], components, flows, artifact, ranges[:1])
    ctx = artifact["threats"][0]["verification_context"]
    if mutation == "outside-job":
        ctx["variants"][0]["evidence"] = [evidence[1]]
        components = components[:1]
    elif mutation == "unread":
        ctx["variants"][0]["evidence"] = [evidence[1]]
    elif mutation == "stale":
        ctx["variants"][0]["evidence"][0]["sha256"] = "0" * 64
    else:
        ctx["variants"].append(copy.deepcopy(ctx["variants"][0]))
    with pytest.raises((ExchangeError, ValueError)):
        stage.validate_stride(scope, components[0], components, flows, artifact, ranges[:1])


@pytest.mark.parametrize("mutation", ["unread", "stale", "duplicate"])
def test_a_context_that_alone_keeps_a_survey_result_rejected_goes_and_the_findings_stay(tmp_path, mutation):
    """REQ-049: after the last correction a faulty runtime context costs the context, not the survey job."""
    scope, components, evidence, ranges, identity = sources(tmp_path)
    artifact = stride(components[0], evidence[0], identity)
    artifact["threats"][0]["verification_context"] = context(copy.deepcopy(evidence[0]))
    ctx = artifact["threats"][0]["verification_context"]
    if mutation == "unread":
        ctx["variants"][0]["evidence"] = [evidence[1]]
    elif mutation == "stale":
        ctx["variants"][0]["evidence"][0]["sha256"] = "0" * 64
    else:
        ctx["variants"].append(copy.deepcopy(ctx["variants"][0]))
    flows = dict(component_inventory_fingerprint=FP, data_flows=[])
    with pytest.raises((ExchangeError, ValueError)) as rejected:
        stage.validate_stride(scope, components[0], components, flows, artifact, ranges[:1])
    kept = stage.stride_salvage(copy.deepcopy(artifact), rejected.value)
    stage.validate_stride(scope, components[0], components, flows, kept, ranges[:1])
    assert [t["local_id"] for t in kept["threats"]] == [t["local_id"] for t in artifact["threats"]]
    assert not any("verification_context" in t for t in kept["threats"])
    # Without a context to drop there is nothing to salvage: any other fault keeps the result rejected.
    assert stage.stride_salvage(copy.deepcopy(kept), rejected.value) is None


@pytest.mark.parametrize("mutation", ["version", "authority", "oversize", "evidence", "order", "unknowns"])
def test_context_schema_rejects_malformed_data(mutation):
    schema = json.loads((ROOT / "schemas/verification-context.schema.json").read_text())
    validator = Draft202012Validator(schema)
    value = context({"file": "routes.py", "line": 1})
    assert validator.is_valid(value)
    if mutation == "version":
        value["version"] = 2
    elif mutation == "authority":
        value["allow_intrusive"] = True
    elif mutation == "oversize":
        value["variants"][0]["mechanism"]["expression"] = "x" * 3001
    elif mutation == "evidence":
        value["variants"][0]["evidence"] = []
    elif mutation == "order":
        value["variants"][0]["processing"][0]["operation"] = "run-shell"
    else:
        value["variants"][0].pop("unknowns")
    assert not validator.is_valid(value)


def test_combined_findings_keep_distinct_variants():
    first = _stride_threat(verification_context=context({"file": "routes.py", "line": 1}))
    second = copy.deepcopy(first)
    second["verification_context"]["variants"][0]["request"]["path"] = "/other"
    survivor = copy.deepcopy(first)
    _merge_member_metadata(survivor, [first, second, first], systemic=True)
    variants = survivor["verification_context"]["variants"]
    assert [v["request"]["path"] for v in variants] == ["/search", "/other"]
    assert len({v["id"] for v in variants}) == 2
    assert first["verification_context"]["variants"][0]["id"] == "search"


@pytest.mark.parametrize("role", ["stride_analyzer", "test_case_investigator", "open_reviewer"])
def test_every_finding_role_receives_runtime_context_guidance(role):
    from orchestrator.orchestration_controller import _assessment_role_instructions

    prompt = _assessment_role_instructions(role, "Inspect this component.")
    # REQ-049: expected for every finding an input path reaches, and named where each finding's fields are listed.
    assert "Add `verification_context` version 1 in this same response to every finding that an evidenced" in prompt
    assert "optional `verification_context`" not in prompt
    assert "and `verification_context` when an input path reaches it" in prompt
    assert "processing` in execution order" in prompt
    assert "negative controls" in prompt and "only served evidence" in prompt
    assert "Do not contact a running application" in prompt
