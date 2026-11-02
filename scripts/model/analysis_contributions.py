"""Recorded contributions of assessment steps; source locations are not semantic novelty."""

from __future__ import annotations

import json
import math
import stat
from pathlib import Path

import yaml
from shared._atomic_io import atomic_write_text
from shared._finding_state import evidence_established

ROLES = {
    "survey": ("stride_analyzer",),
    "verification": ("test_case_investigator",),
    "evidence_review": ("evidence_verifier",),
    "abuse_cases": ("abuse_case_deriver", "abuse_case_verifier"),
}


def _read(path: Path):
    from runtime.assessment_state import MAX_DELIVERABLE_BYTES

    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_DELIVERABLE_BYTES:
        raise ValueError("Contribution input is not a bounded regular artifact")
    return json.loads(path.read_text(encoding="utf-8"))


def _locations(findings):
    """Compare every preserved location, including ones inside a systemic finding."""
    result = set()
    for finding in findings:
        evidence = finding.get("evidence") or []
        rows = evidence if isinstance(evidence, list) else [evidence]
        for row in [*rows, *(finding.get("instances") or [])]:
            if isinstance(row, dict) and isinstance(row.get("file"), str) and type(row.get("line")) is int:
                result.add((row["file"], row["line"]))
    return result


def compare(survey, verification, decisions, before_abuse, after_abuse, costs=None):
    """Missing evidence means unknown; different anchors do not prove different problems."""
    costs = costs or {}
    survey_locations = _locations(survey) if survey is not None else None
    verification_locations = _locations(verification) if verification is not None else None
    new = (
        verification_locations - survey_locations
        if survey_locations is not None and verification_locations is not None
        else None
    )
    prior = {row.get("t_id"): row for row in before_abuse} if before_abuse is not None else None
    after = {row.get("t_id"): row for row in after_abuse}
    added = _locations(after_abuse) - _locations(before_abuse) if prior is not None else None
    strengthened = (
        sum(evidence_established(row) and not evidence_established(prior.get(fid)) for fid, row in after.items())
        if prior is not None
        else None
    )
    contradicted = (
        sum(
            bool(row.get("evidence_review_contradicted"))
            and not bool(prior.get(fid, {}).get("evidence_review_contradicted"))
            for fid, row in after.items()
        )
        if prior is not None
        else None
    )
    rows = [
        {
            "step": "survey",
            "additional_locations": len(survey_locations) if survey_locations is not None else None,
            "repeated_locations": None,
            "distinct_problems_added": None,
            "stronger_evidence": None,
            "contradictions": None,
        },
        {
            "step": "verification",
            "additional_locations": len(new) if new is not None else None,
            "repeated_locations": len(verification_locations & survey_locations) if new is not None else None,
            "distinct_problems_added": 0 if verification == [] else None,
            "stronger_evidence": None,
            "contradictions": None,
        },
        {
            "step": "evidence_review",
            "additional_locations": None,
            "repeated_locations": None,
            "distinct_problems_added": 0 if decisions is not None else None,
            "stronger_evidence": sum(d.get("verdict") == "verified" for d in decisions)
            if decisions is not None
            else None,
            "contradictions": sum(d.get("verdict") == "refuted" for d in decisions) if decisions is not None else None,
        },
        {
            "step": "abuse_cases",
            "additional_locations": len(added) if added is not None else None,
            "repeated_locations": None,
            "distinct_problems_added": 0 if prior is not None and not (after.keys() - prior.keys()) else None,
            "stronger_evidence": strengthened,
            "contradictions": contradicted,
        },
    ]
    for row in rows:
        value = costs.get(row["step"])
        row["recorded_usd"] = value if type(value) in (int, float) and math.isfinite(value) and value >= 0 else None
    return {
        "schema_version": 1,
        "steps": rows,
        "comparison_limit": "Locations count source anchors, not independent weaknesses. Semantic novelty at different anchors is unknown. Evidence counts are recorded review decisions, not executed attacks. Missing input or accounting is unknown.",
    }


def persist(workspace, jobs, names):
    """Use only receipted current-run jobs; add no model call or external destination."""
    from runtime.assessment_jobs import digest

    from model.enrichment_pass import EnrichmentContinuation

    workspace = Path(workspace)
    grouped = {role: [] for roles in ROLES.values() for role in roles}
    complete = hasattr(jobs, "directory")
    if complete:
        try:
            for receipt_path in sorted(Path(jobs.directory).glob("*.receipt.json")):
                receipt = _read(receipt_path)
                if receipt.get("role") not in grouped:
                    continue
                artifact = _read(receipt_path.with_name(receipt_path.name.replace(".receipt.json", ".json")))
                if digest(artifact) != receipt["artifact_sha256"]:
                    raise ValueError("Contribution artifact does not match its receipt")
                grouped[receipt["role"]].append(artifact)
        except (OSError, ValueError, KeyError, TypeError):
            complete = False
    survey = [] if complete else None
    if complete:
        for artifact in grouped["stride_analyzer"]:
            for finding in artifact.get("threats", []):
                evidence = finding.get("evidence") or {}
                survey.append(
                    {
                        "evidence": {
                            "file": names.qualify(evidence["repository_id"], evidence["file"]),
                            "line": evidence["line"],
                        }
                    }
                )
    try:
        verification = _read(workspace / ".test-case-pilot.json")["findings"]
    except (OSError, ValueError, KeyError, TypeError):
        verification = None
    try:
        before = _read(workspace / ".analysis-before-abuse.json")["threats"]
    except (OSError, ValueError, KeyError, TypeError):
        before = None
    after = _read(workspace / ".threats-merged.json")["threats"]
    decisions = [d for a in grouped["evidence_verifier"] for d in a.get("decisions", [])] if complete else None
    costs = {}
    budget = getattr(jobs, "budget", None)
    accepted = getattr(jobs, "accepted_results", {})
    if budget is not None and not getattr(budget, "subscription", True) and not getattr(budget, "reused_usd", 0):
        for step, roles in ROLES.items():
            selectors = [row["selector"] for row in accepted.values() if row["role"] in roles]
            selectors += [row["selector"] for row in getattr(jobs, "gaps", []) if row.get("role") in roles]
            costs[step] = budget.charged_of(*set(selectors))
    result = compare(survey, verification, decisions, before, after, costs)
    path = workspace / "threat-model.yaml"
    model = yaml.safe_load(path.read_text(encoding="utf-8"))
    continuation = EnrichmentContinuation(model)
    model["analysis_contributions"] = result
    continuation.refresh(model)
    atomic_write_text(path, yaml.safe_dump(model, sort_keys=False, allow_unicode=True))
    return result


def markdown(block):
    """A fixed vocabulary and numeric cells keep stored model text out of the table."""
    if not isinstance(block, dict) or block.get("schema_version") != 1:
        return []
    names = {
        "survey": "Survey",
        "verification": "Verification",
        "evidence_review": "Evidence review",
        "abuse_cases": "Abuse cases",
    }
    lines = [
        "### Contribution of analysis steps",
        "",
        "Source anchors count locations, not independent weaknesses. Different anchors can describe the same problem. Semantic novelty and missing measurements are shown as unknown. Review confirmations do not establish an executed attack.",
        "",
        "| Step | Additional locations | Repeated locations | New distinct problems | Stronger evidence | Contradictions | Recorded cost (USD) |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in block.get("steps") or []:
        if not isinstance(row, dict) or row.get("step") not in names:
            continue
        cells = []
        for key in (
            "additional_locations",
            "repeated_locations",
            "distinct_problems_added",
            "stronger_evidence",
            "contradictions",
            "recorded_usd",
        ):
            value = row.get(key)
            valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
            cells.append((f"{value:.2f}" if key == "recorded_usd" else str(value)) if valid else "unknown")
        lines.append("| " + " | ".join([names[row["step"]], *cells]) + " |")
    lines += [
        "",
        "Verification is compared with the original survey, including locations preserved inside consolidated findings. Abuse cases are compared with the findings immediately before their checks. Evidence review counts its recorded decisions. Costs include charged failed attempts when the run can attribute them; subscription use or unavailable accounting is unknown.",
        "",
    ]
    return lines
