#!/usr/bin/env python3
"""model/case_outcomes.py: outcomes of the security test case catalog (REQ-040).

Without model calls this module does two things with the deterministic scanner
results of a run:

* ``annotate_threats`` links every scanner finding to the test cases whose
  starting points name its rule (``rule_ids`` and ``test_case_ids``).
* ``evaluate`` derives one outcome per ``rules`` test case from the recorded
  result of each of its rules: violated, satisfied, or not applicable.

A test case is ``control`` only when every applicable rule is satisfied, with
a recorded result for each. A missing scanner result is never read as
satisfied. Outcomes of ``seeded`` and ``model`` test cases need a model
investigation and are not produced here.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "data" / "test-cases.yaml"
SCHEMA = ROOT / "schemas" / "test-cases.schema.yaml"

SATISFIED = "satisfied"
VIOLATED = "violated"
NOT_APPLICABLE = "not_applicable"
UNKNOWN = "unknown"

# Keys of a threat that name the scanner rule behind it.
_RULE_KEYS = ("source_check_id", "config_check_id")


def load_catalog(path: Path = CATALOG) -> dict[str, Any]:
    """The shipped catalog, validated against its schema."""
    catalog = yaml.safe_load(path.read_text(encoding="utf-8"))
    schema = yaml.safe_load(SCHEMA.read_text(encoding="utf-8"))
    errors = sorted(Draft202012Validator(schema).iter_errors(catalog), key=str)
    if errors:
        raise ValueError(f"test case catalog is invalid: {errors[0].message}")
    return catalog


def rule_index(catalog: dict[str, Any]) -> dict[str, list[str]]:
    """Test case IDs per scanner rule, in catalog order."""
    index: dict[str, list[str]] = {}
    for case in catalog["test_cases"]:
        for rule in case["starting_points"]["rules"]:
            index.setdefault(rule, []).append(case["id"])
    return index


def threat_rule_ids(threat: dict[str, Any]) -> list[str]:
    """Scanner rules behind a threat, including those of its consolidated instances."""
    found: list[str] = []
    for holder in [threat, *(threat.get("instances") or [])]:
        if not isinstance(holder, dict):
            continue
        for key in _RULE_KEYS:
            value = holder.get(key)
            if isinstance(value, str) and value and value not in found:
                found.append(value)
    return found


def annotate_threats(threats: list[dict[str, Any]], catalog: dict[str, Any]) -> int:
    """Set ``rule_ids`` and ``test_case_ids`` on threats whose rule seeds a test case.

    Returns how many threats were linked. Threats without a catalog rule are left unchanged."""
    index = rule_index(catalog)
    linked = 0
    for threat in threats:
        rules = [rule for rule in threat_rule_ids(threat) if rule in index]
        if not rules:
            continue
        cases: list[str] = []
        for rule in rules:
            cases.extend(case for case in index[rule] if case not in cases)
        threat["rule_ids"] = rules
        threat["test_case_ids"] = cases
        linked += 1
    return linked


def rule_statuses(
    catalog: dict[str, Any],
    config_scan: dict[str, Any] | None,
    architecture_coverage: dict[str, Any] | None,
) -> dict[str, str]:
    """Recorded outcome per scanner rule: violated, satisfied, or not applicable.

    A rule without an entry is absent from the result and reads as unknown."""
    statuses: dict[str, str] = {}
    if isinstance(config_scan, dict):
        if "rules_evaluated" in config_scan:
            for row in config_scan["rules_evaluated"]:
                statuses[row["check_id"]] = row["status"]
        elif "parse_error" in config_scan and str(config_scan["parse_error"]).startswith("skipped"):
            # The scan did not run because the repository has no IaC surface.
            for rules in (case["starting_points"]["rules"] for case in catalog["test_cases"]):
                statuses.update({rule: NOT_APPLICABLE for rule in rules if rule.startswith("IAC-")})
    if isinstance(architecture_coverage, dict):
        for row in architecture_coverage.get("rules_evaluated", []):
            if not row.get("applies") or row.get("status") == "not_applicable":
                statuses[row["rule_id"]] = NOT_APPLICABLE
            elif row.get("status") == "present":
                statuses[row["rule_id"]] = SATISFIED
            else:
                statuses[row["rule_id"]] = VIOLATED
    return statuses


def _outcome(statuses: list[str]) -> tuple[str, str]:
    violated = statuses.count(VIOLATED)
    satisfied = statuses.count(SATISFIED)
    unknown = statuses.count(UNKNOWN)
    applicable = violated + satisfied + unknown
    if violated:
        return "finding", f"{violated} of {applicable} applicable rules violated"
    if not applicable:
        return "not_applicable", "no rule of this test case applies to the examined sources"
    if not satisfied:
        return "undecidable", "no scanner result was recorded for the applicable rules"
    if unknown:
        return "partial", f"{satisfied} of {applicable} applicable rules satisfied; the others have no recorded result"
    return "control", f"all {applicable} applicable rules satisfied"


def evaluate(
    catalog: dict[str, Any],
    statuses: dict[str, str],
    threats: list[dict[str, Any]],
    disabled: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    """One result per ``rules`` test case, from the recorded outcome of each of its rules.

    ``disabled`` maps test case IDs to the reason an operator disabled them; a disabled test case
    reports no outcome from its rules, but its findings stay in the threat list."""
    disabled = disabled or {}
    results = []
    for case in catalog["test_cases"]:
        if case["mode"] != "rules":
            continue
        rules = case["starting_points"]["rules"]
        rows = [{"rule_id": rule, "status": statuses.get(rule, UNKNOWN)} for rule in rules]
        if case["id"] in disabled:
            outcome, reason = "disabled", disabled[case["id"]]
        else:
            outcome, reason = _outcome([row["status"] for row in rows])
        findings = [
            threat.get("id") or threat.get("t_id")
            for threat in threats
            if case["id"] in threat.get("test_case_ids", []) and (threat.get("id") or threat.get("t_id"))
        ]
        applicable = [row for row in rows if row["status"] != NOT_APPLICABLE]
        results.append(
            {
                "test_case_id": case["id"],
                "aspect": case["aspect"],
                "scope": "repository",
                "outcome": outcome,
                "reason": reason,
                "evidence_basis": "deterministic",
                "candidates": {
                    "applicable": len(applicable),
                    "evidenced": sum(row["status"] == SATISFIED for row in rows),
                },
                "rules": rows,
                "finding_ids": findings,
            }
        )
    return results


def build_block(
    workspace: Path,
    threats: list[dict[str, Any]],
    disabled: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Annotate ``threats`` and return the ``test_case_results`` block for threat-model.yaml.

    Reads the scanner sidecars of ``workspace``; a sidecar that is missing or unreadable leaves its
    rules unknown, so the affected test cases report undecidable instead of control."""
    catalog = load_catalog()
    annotate_threats(threats, catalog)
    statuses = rule_statuses(
        catalog,
        _read_json(workspace / ".config-scan-findings.json"),
        _read_json(workspace / ".architecture-coverage.json"),
    )
    return {
        "catalog_version": catalog["catalog_version"],
        "results": evaluate(catalog, statuses, threats, disabled),
    }


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None
