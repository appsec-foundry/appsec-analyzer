"""Contribution measurements retain uncertainty instead of equating anchors with weaknesses."""

import json
import os
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from jsonschema import Draft202012Validator
from model.analysis_contributions import compare, markdown, persist
from model.enrichment_pass import stamp, valid_receipt
from runtime.assessment_jobs import digest


def finding(file="api/orders.py", line=12, **extra):
    return {"t_id": "T-001", "evidence": {"file": file, "line": line}, **extra}


def rows(result):
    return {row["step"]: row for row in result["steps"]}


def test_comparison_counts_all_systemic_locations_and_never_claims_semantic_novelty():
    survey = [finding(instances=[{"file": "api/checkout.py", "line": 30}])]
    verification = [finding(), finding("api/checkout.py", 30), finding("api/refunds.py", 40)]
    result = rows(compare(survey, verification, [], survey, survey, {"verification": 1.25}))
    assert result["verification"]["additional_locations"] == 1
    assert result["verification"]["repeated_locations"] == 2
    assert result["verification"]["distinct_problems_added"] is None
    assert result["verification"]["recorded_usd"] == 1.25
    assert result["abuse_cases"]["distinct_problems_added"] == 0


def test_same_anchor_can_hold_a_different_claim_so_it_never_proves_zero_new_problems():
    result = rows(compare([finding()], [finding(cwe="CWE-639")], [], [], []))
    assert result["verification"]["additional_locations"] == 0
    assert result["verification"]["distinct_problems_added"] is None


def test_missing_input_or_cost_is_unknown_and_evidence_changes_are_measured():
    after = [finding(evidence_basis="llm-verified")]
    result = compare(None, None, None, None, after)
    assert all(row["recorded_usd"] is None for row in result["steps"])
    assert rows(result)["verification"]["additional_locations"] is None
    assert rows(result)["abuse_cases"]["stronger_evidence"] is None
    result = rows(
        compare([], [], [{"verdict": "verified"}, {"verdict": "refuted"}], [finding(evidence_basis="ambiguous")], after)
    )
    assert result["abuse_cases"]["stronger_evidence"] == 1
    assert result["evidence_review"]["contradictions"] == 1


def test_readable_table_does_not_render_untrusted_strings_or_infinite_costs():
    block = compare([], [], [], [], [], {"verification": float("inf")})
    block["steps"].append({"step": "<script>"})
    text = "\n".join(markdown(block))
    assert "<script>" not in text
    assert "unknown" in text
    assert "independent weaknesses" in text
    assert markdown(None) == []


def test_report_rendering_import_needs_only_the_packaged_engine(tmp_path):
    scripts = Path(__file__).parents[1] / "scripts"
    result = subprocess.run(
        [sys.executable, "-c", "from model.analysis_contributions import markdown; assert markdown(None) == []"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(scripts)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("tamper", [False, True])
@pytest.mark.parametrize("receipt_state", ["valid", "missing", "stale"])
def test_persistence_uses_receipted_jobs_and_charged_cost_without_model_calls(tmp_path, tamper, receipt_state):
    directory = tmp_path / "jobs"
    directory.mkdir()
    artifact = {"threats": [finding()]}
    artifact["threats"][0]["evidence"]["repository_id"] = "repo-a"
    (directory / "job.json").write_text(json.dumps(artifact))
    (directory / "job.receipt.json").write_text(
        json.dumps({"role": "stride_analyzer", "artifact_sha256": digest(artifact)})
    )
    if tamper:
        (directory / "job.json").write_text('{"threats": []}')
    for name, data in [
        (".test-case-pilot.json", {"findings": []}),
        (".analysis-before-abuse.json", {"threats": []}),
        (".threats-merged.json", {"threats": []}),
    ]:
        (tmp_path / name).write_text(json.dumps(data))
    model = {"meta": {}, "threats": []}
    if receipt_state != "missing":
        stamp(model)
    if receipt_state == "stale":
        model["meta"]["title"] = "Changed since enrichment"
    (tmp_path / "threat-model.yaml").write_text(yaml.safe_dump(model))
    jobs = SimpleNamespace(
        directory=directory,
        accepted_results={"x": {"role": "stride_analyzer", "selector": "survey:x"}},
        gaps=[{"role": "evidence_verifier", "selector": "evidence:failed"}],
        budget=SimpleNamespace(
            subscription=False,
            reused_usd=0,
            charged_of=lambda *s: sum({"survey:x": 0.75, "evidence:failed": 0.25}.get(name, 0) for name in s),
        ),
    )
    result = persist(tmp_path, jobs, SimpleNamespace(qualify=lambda rid, path: path))
    assert rows(result)["survey"]["additional_locations"] == (None if tamper else 1)
    assert rows(result)["survey"]["recorded_usd"] == 0.75
    assert rows(result)["evidence_review"]["recorded_usd"] == 0.25
    saved = yaml.safe_load((tmp_path / "threat-model.yaml").read_text())
    assert saved["analysis_contributions"] == result
    assert valid_receipt(saved) == (receipt_state == "valid")
    if receipt_state == "valid":
        assert saved["meta"]["enrichment_pass"]["completed_at"] == model["meta"]["enrichment_pass"]["completed_at"]
    schema = yaml.safe_load((Path(__file__).parents[1] / "schemas/threat-model.output.schema.yaml").read_text())
    Draft202012Validator(schema["properties"]["analysis_contributions"]).validate(result)
