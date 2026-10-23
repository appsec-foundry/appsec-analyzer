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
satisfied.

Outcomes of ``seeded`` and ``model`` test cases need a model investigation
(REQ-040 pilot). ``assess_candidates`` applies the deterministic rules to the
answered candidates of one test case and runs its post-checks;
``component_outcome`` derives the outcome of one test case for one component
from them, and ``investigation_results`` does both for an accepted
investigation reply. The model's proposed outcome is recorded only when it
differs, and no model-written text reaches a result.
"""

from __future__ import annotations

import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

import yaml
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
CATALOG = ROOT / "data" / "test-cases.yaml"
SCHEMA = ROOT / "schemas" / "test-cases.schema.yaml"
# Workspace sidecar of the model-backed pilot: component results and findings
# (orchestrator/assessment_test_cases.py).
PILOT_SIDECAR = ".test-case-pilot.json"

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
    rules unknown, so the affected test cases report undecidable instead of control. The component
    results of the pilot sidecar follow the rules results unchanged."""
    catalog = load_catalog()
    annotate_threats(threats, catalog)
    statuses = rule_statuses(
        catalog,
        _read_json(workspace / ".config-scan-findings.json"),
        _read_json(workspace / ".architecture-coverage.json"),
    )
    pilot = _read_json(workspace / PILOT_SIDECAR) or {}
    block = {
        "catalog_version": catalog["catalog_version"],
        "results": evaluate(catalog, statuses, threats, disabled) + list(pilot.get("results") or []),
    }
    if pilot.get("incomplete_aspects"):
        block["incomplete_aspects"] = list(pilot["incomplete_aspects"])
    return block


def pilot_findings(workspace: Path) -> list[dict[str, Any]]:
    """The findings of the verification sidecar, which ``combine_methods`` links with the survey's."""
    return list((_read_json(workspace / PILOT_SIDECAR) or {}).get("findings") or [])


#: Lines apart at which a survey and a verification finding in one file count as the same code location.
SAME_LOCATION_LINES = 3


def _survey_locations(threat: Mapping[str, Any]) -> list[tuple[str, int]]:
    rows = [row for row in threat.get("evidence") or [] if isinstance(row, dict)]
    rows += [row for row in threat.get("instances") or [] if isinstance(row, dict)]
    return [(row["file"], row["line"]) for row in rows if row.get("file") and isinstance(row.get("line"), int)]


def _near(location: tuple[str, int], file: str, line: int) -> bool:
    return location[0] == file and abs(location[1] - line) <= SAME_LOCATION_LINES


def combine_methods(
    threats: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    results: list[dict[str, Any]],
    catalog: dict[str, Any] | None = None,
) -> dict[str, int]:
    """Link the survey's findings with verification's at the same code location (REQ-040).

    A verification finding with the same CWE as a survey finding at one of its locations names it in
    ``survey_finding_ids``, and the survey finding names the verification finding and items in
    ``verification``, so the report shows the weakness once. A survey finding at a location where a
    verification item evidenced a control for its CWE records the item and location in
    ``verification_contradicted`` and stays in the report. Survey findings at locations verification
    did not examine stay unchanged. Returns how many findings were linked and contradicted."""
    survey = [threat for threat in threats if threat.get("source") == "stride" and threat.get("id")]
    linked = 0
    for finding in findings:
        evidence = finding.get("evidence") or {}
        if not evidence.get("file") or not isinstance(evidence.get("line"), int):
            continue
        matches = [
            threat
            for threat in survey
            if threat.get("cwe") == finding.get("cwe")
            and any(_near(location, evidence["file"], evidence["line"]) for location in _survey_locations(threat))
        ]
        if not matches:
            continue
        finding["survey_finding_ids"] = [threat["id"] for threat in matches]
        linked += 1
        for threat in matches:
            block = threat.setdefault("verification", {"finding_ids": [], "test_case_ids": []})
            block["finding_ids"].append(finding["id"])
            for case_id in finding.get("test_case_ids") or []:
                if case_id not in block["test_case_ids"]:
                    block["test_case_ids"].append(case_id)
                if case_id not in threat.setdefault("test_case_ids", []):
                    threat["test_case_ids"].append(case_id)
    cwes = {case["id"]: set(case["cwe"]) for case in (catalog or load_catalog())["test_cases"]}
    contradicted = 0
    for threat in survey:
        if threat.get("verification"):
            continue
        rows = [
            {"test_case_id": result["test_case_id"], "file": file, "line": line}
            for result in results
            if threat.get("cwe") in cwes.get(result.get("test_case_id"), ())
            for spot in result.get("control_locations") or []
            for file, line in _survey_locations(threat)
            if _near((file, line), spot["file"], spot["line"])
        ]
        if rows:
            unique = {(row["test_case_id"], row["file"], row["line"]): row for row in rows}
            threat["verification_contradicted"] = list(unique.values())
            contradicted += 1
    return {"linked": linked, "contradicted": contradicted}


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return document if isinstance(document, dict) else None


# --- model investigations (REQ-040 pilot) -----------------------------------

DOCUMENTATION_REASON = "documentation is not control evidence"
# Fixed text per undecidable reason of an investigation reply; the model's own words never reach a result.
UNDECIDABLE_REASONS = {
    "external-control": "the control would lie outside the examined sources",
    "missing-source": "the examined sources cannot settle the question",
    "conflicting-evidence": "the examined sources contradict each other",
    "finding-dropped": "its finding still broke an evidence, trace or rating rule after the last correction",
}
REPLACEMENT_REASONS = {
    "budget": "the model budget ended before this investigation",
    "failure": "the model investigation returned no acceptable result",
}
NOTHING_EXAMINED_REASON = "the investigation examined no candidate location in the component"
GOAL_NO_FINDING_REASON = "the goal was examined across the component without a weakness beyond its other test cases"
_DOCUMENTATION_SUFFIXES = frozenset({".md", ".rst", ".txt", ".adoc"})


def is_documentation(path: str) -> bool:
    """Whether a repository-relative path is documentation, which is never control evidence."""
    parts = PurePosixPath(path).parts
    return PurePosixPath(path).suffix.lower() in _DOCUMENTATION_SUFFIXES or "docs" in (p.lower() for p in parts[:-1])


def assess_candidates(
    case: Mapping[str, Any],
    answer: Mapping[str, Any],
    precheck: Iterable[Mapping[str, Any]],
    facts: Mapping[str, Any] | None = None,
    *,
    repository_id: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """``(candidates, post_checks)``: the answered candidates of one test case after the deterministic rules.

    ``answer`` is the test case's entry of an accepted investigation reply,
    ``precheck`` the controller's pre-check candidates of it, and ``facts``
    the route facts of ``repository_id``, the component's repository. A
    control supported only by documentation becomes undecidable. A weakness
    or control claim at a route runs the test case's post-checks, except the
    variant search: a contradiction makes the candidate undecidable with the
    check's reason, and the claim counts as confirmed only when every check
    confirms it. A route of a model candidate in another repository is not
    checked, so its claim stays model-evidenced.
    """
    from model.case_postchecks import CONFIRMED, CONTRADICTED, run_check

    fixed = {row["candidate_id"]: row for row in precheck}
    checks = [entry for entry in case["post"] if entry.get("check") != "variant-search"]
    records, rows = [], []
    for candidate in answer["candidates"]:
        record = {
            "candidate_id": candidate["candidate_id"],
            "origin": candidate["origin"],
            "claim": candidate["status"],
            "status": candidate["status"],
            "reason": None,
            "confirmed": False,
            "contradicted": False,
            "route_id": None,
            "rule_ids": [],
            "finding_ids": list(candidate.get("finding_ids") or []),
        }
        records.append(record)
        if candidate["origin"] == "pre-check":
            own = fixed.get(candidate["candidate_id"], {})
            anchor, record["route_id"] = own.get("anchor"), own.get("route_id")
            record["rule_ids"] = list(own.get("rule_ids") or [])
        else:
            anchor = candidate["anchor"]
            if repository_id is None or anchor.get("repository_id") == repository_id:
                record["route_id"] = candidate.get("route_id")
        if anchor and (repository_id is None or anchor.get("repository_id", repository_id) == repository_id):
            record["anchor"] = {"file": anchor["file"], "line": anchor["line"]}
        if candidate["status"] == "undecidable":
            record["reason"] = UNDECIDABLE_REASONS[candidate["undecidable_reason"]]
            continue
        if candidate["status"] == "control" and all(is_documentation(row["file"]) for row in candidate["evidence"]):
            record.update(status="undecidable", reason=DOCUMENTATION_REASON)
            continue
        if candidate["status"] not in ("weakness", "control") or not (anchor and checks) or facts is None:
            continue
        # Only site-reached judges a location without a route.
        usable = checks if record["route_id"] else [entry for entry in checks if entry.get("check") == "site-reached"]
        if not usable:
            continue
        params = {"route_id": record["route_id"], "anchor": {"file": anchor["file"], "line": anchor["line"]}}
        results = []
        for entry in usable:
            result = run_check(entry, candidate["status"], params, facts)
            results.append(result)
            rows.append(
                {
                    "candidate_id": candidate["candidate_id"],
                    "check": entry["check"],
                    **({"guard": entry["guard"]} if entry.get("guard") else {}),
                    **({"site": entry["site"]} if entry.get("site") else {}),
                    "claim": candidate["status"],
                    "result": result["result"],
                    "reason": result["reason"],
                }
            )
        contradiction = next((result for result in results if result["result"] == CONTRADICTED), None)
        if contradiction:
            record.update(status="undecidable", reason=contradiction["reason"], contradicted=True)
        else:
            record["confirmed"] = all(result["result"] == CONFIRMED for result in results)
    return records, rows


def component_outcome(
    case: Mapping[str, Any],
    component_id: str,
    candidates: Iterable[Mapping[str, Any]],
    *,
    unexamined: int = 0,
    proposed_outcome: str | None = None,
    post_checks: Iterable[Mapping[str, str]] = (),
    unreviewed_variants: Mapping[str, Any] | None = None,
    finding_ids: Iterable[str] = (),
    statuses: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """The result of one test case for one component, derived from its assessed candidates.

    ``candidates`` are records of ``assess_candidates``; ``unexamined``
    counts candidates that did not fit the investigation. With C the
    candidates that were not rejected:

    1. a weakness that no post-check contradicts makes a ``finding``;
    2. otherwise a control at every candidate of a non-empty C, with none
       unexamined, makes a ``control``;
    3. otherwise at least one control makes a ``partial``;
    4. otherwise an undecidable or unexamined candidate makes the test case
       ``undecidable``, and so does a test case without any candidate, since
       nothing was examined; only a goal test case, whose search covers the
       component rather than single locations, keeps the model's
       ``no_finding`` without candidates;
    5. otherwise it is ``no_finding``, also when every candidate was rejected.

    A control or partial result is ``deterministic`` only when every control
    claim is post-check confirmed and the candidate set did not come from
    the model alone; a finding only when every weakness claim is confirmed.
    The reason says where a control rests on model review only.
    """
    candidates = list(candidates)
    if type(unexamined) is not int or unexamined < 0:
        raise ValueError("unexamined must be a non-negative integer")
    examined = [entry for entry in candidates if entry["status"] != "rejected"]
    weaknesses = [entry for entry in examined if entry["status"] == "weakness"]
    controls = [entry for entry in examined if entry["status"] == "control"]
    undecided = [entry for entry in examined if entry["status"] == "undecidable"]
    total = len(examined) + unexamined
    left_out = f"; {unexamined} not examined" if unexamined else ""
    basis = "model"
    if weaknesses:
        outcome = "finding"
        reason = f"weakness at {len(weaknesses)} of {total} candidate locations" + (
            f"; {_controlled(controls, str(len(controls)))}" if controls else ""
        )
        basis = "deterministic" if all(entry["confirmed"] for entry in weaknesses) else "model"
    elif controls and len(controls) == len(examined) and not unexamined:
        outcome, reason = "control", _controlled(controls, f"all {total} candidate locations")
    elif controls:
        outcome = "partial"
        reason = _controlled(controls, f"{len(controls)} of {total} candidate locations") + left_out
    elif undecided:
        outcome = "undecidable"
        reason = f"{len(undecided)} of {total} candidate locations undecidable: {undecided[0]['reason']}{left_out}"
    elif unexamined:
        outcome, reason = "undecidable", f"{unexamined} of {total} candidate locations did not fit the investigation"
    elif candidates:
        outcome = "no_finding"
        reason = (
            f"no weakness or control at {len(examined)} examined candidate locations"
            if examined
            else "every candidate location was rejected with evidence"
        )
    elif case.get("goal") and proposed_outcome == "no_finding":
        outcome, reason = "no_finding", GOAL_NO_FINDING_REASON
    else:
        outcome, reason = "undecidable", NOTHING_EXAMINED_REASON
    if outcome in ("control", "partial"):
        from_precheck = any(entry["origin"] == "pre-check" for entry in examined)
        basis = "deterministic" if from_precheck and all(entry["confirmed"] for entry in controls) else "model"
    rules = case["starting_points"]["rules"] if statuses is not None else []
    row = {
        "test_case_id": case["id"],
        "aspect": case["aspect"],
        "scope": "component",
        "component_id": component_id,
        "outcome": outcome,
        "reason": reason,
        "evidence_basis": basis,
        "candidates": {
            "applicable": total,
            "evidenced": len(controls),
            "weaknesses": len(weaknesses),
            "rejected": len(candidates) - len(examined),
            "undecidable": len(undecided),
            "model_added": sum(entry["origin"] == "model" for entry in candidates),
            "unexamined": unexamined,
        },
        "rules": [{"rule_id": rule, "status": (statuses or {}).get(rule, UNKNOWN)} for rule in rules],
        "finding_ids": list(finding_ids),
        "post_checks": [dict(check) for check in post_checks],
    }
    if proposed_outcome is not None and proposed_outcome != outcome:
        row["proposed_outcome"] = proposed_outcome
    if unreviewed_variants is not None:
        row["unreviewed_variants"] = {
            "count": unreviewed_variants["count"],
            "route_ids": list(unreviewed_variants["route_ids"]),
        }
    return row


def _controlled(controls: list[Mapping[str, Any]], where: str) -> str:
    """Where a control is evidenced, naming the claims that only model review supports."""
    unconfirmed = sum(not entry["confirmed"] for entry in controls)
    if not unconfirmed:
        return f"control evidenced at {where}"
    if unconfirmed == len(controls):
        return f"control evidenced by model review only at {where}"
    return f"control evidenced at {where}, by model review only at {unconfirmed} of them"


def investigation_results(
    reply: Mapping[str, Any],
    component_id: str,
    *,
    precheck: Mapping[str, Iterable[Mapping[str, Any]]],
    overflow: Mapping[str, int] | None = None,
    facts: Mapping[str, Any] | None = None,
    repository_id: str | None = None,
    statuses: Mapping[str, str] | None = None,
    catalog: dict[str, Any] | None = None,
    replaced: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """``{results, dropped_finding_ids}`` of an accepted investigation reply for one component.

    ``precheck`` and ``overflow`` map each test case ID to the controller's
    pre-check candidates and the number left out of the packet. When several
    jobs shared the candidates, ``reply`` combines the accepted ones, and
    ``replaced`` maps each pre-check candidate of a job the budget or a model
    failure replaced to that cause: such a candidate is undecidable with the
    cause's fixed reason. A finding is dropped from the merge input when
    every weakness candidate it reports was contradicted by a post-check.
    ``finding_ids`` of a result are the reply's local IDs of the findings
    kept for it.
    """
    from model.case_postchecks import variant_search

    cases = {case["id"]: case for case in (catalog or load_catalog())["test_cases"]}
    overflow = overflow or {}
    replaced = replaced or {}
    assessed = {}
    for answer in reply["test_cases"]:
        case = cases[answer["test_case_id"]]
        precheck_rows = list(precheck.get(case["id"], ()))
        records, checks = assess_candidates(case, answer, precheck_rows, facts, repository_id=repository_id)
        records += [
            _replaced_record(row, replaced[row["candidate_id"]])
            for row in precheck_rows
            if row["candidate_id"] in replaced
        ]
        assessed[case["id"]] = (case, answer, records, checks)
    records = {record["candidate_id"]: record for _, _, rows, _ in assessed.values() for record in rows}
    dropped = [
        finding["local_id"]
        for finding in reply["findings"]
        if all(records.get(candidate, {}).get("contradicted") for candidate in finding["candidate_ids"])
    ]
    results = []
    for case_id, (case, answer, candidates, checks) in assessed.items():
        variants = None
        if facts is not None and any(entry.get("check") == "variant-search" for entry in case["post"]):
            reviewed = [record["route_id"] for record in candidates if record["route_id"]]
            variants = variant_search(case, component_id, facts, reviewed)["unreviewed_variants"]
        row = component_outcome(
            case,
            component_id,
            candidates,
            unexamined=overflow.get(case_id, 0),
            proposed_outcome=answer["proposed_outcome"],
            post_checks=checks,
            unreviewed_variants=variants,
            finding_ids=[
                finding["local_id"]
                for finding in reply["findings"]
                if case_id in finding["test_case_ids"] and finding["local_id"] not in dropped
            ],
            statuses=statuses,
        )
        # The survey findings these locations contradict are marked when both methods are combined.
        controlled = {
            (record["anchor"]["file"], record["anchor"]["line"])
            for record in candidates
            if record["status"] == "control" and record.get("anchor")
        }
        if controlled:
            row["control_locations"] = [{"file": file, "line": line} for file, line in sorted(controlled)]
        results.append(row)
    return {"results": results, "dropped_finding_ids": dropped}


def _replaced_record(row: Mapping[str, Any], cause: str) -> dict[str, Any]:
    """The record of a pre-check candidate whose job was replaced, in the shape of ``assess_candidates``."""
    return {
        "candidate_id": row["candidate_id"],
        "origin": "pre-check",
        "claim": None,
        "status": "undecidable",
        "reason": REPLACEMENT_REASONS[cause],
        "confirmed": False,
        "contradicted": False,
        "route_id": row.get("route_id"),
        "rule_ids": list(row.get("rule_ids") or []),
        "finding_ids": [],
    }


def replacement_result(
    case: Mapping[str, Any], component_id: str, cause: str, *, unexamined: int = 0
) -> dict[str, Any]:
    """The undecidable result of a test case whose investigation the budget or a model failure replaced."""
    if cause not in REPLACEMENT_REASONS:
        raise ValueError("unknown replacement cause")
    row = component_outcome(case, component_id, [], unexamined=unexamined)
    row.update(outcome="undecidable", reason=REPLACEMENT_REASONS[cause], evidence_basis="model")
    return row
