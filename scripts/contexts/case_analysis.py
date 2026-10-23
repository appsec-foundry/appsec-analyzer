"""contexts/case_analysis.py: contracts and reviews of test case investigations (REQ-040 pilot).

The pilot asks one model call per component and aspect to answer the enabled
test cases of that aspect (``test_case_investigator``), or several calls that
share its candidates (``model/case_candidates.batches``), and one call per
component to look for weaknesses that no test case covers
(``open_reviewer``). This module owns their reply contracts, the catalog
text of their instructions, the fields the controller derives in a reply,
the reviews that accept or reject a reply, and the combination of a shared
investigation's accepted replies. It does not sequence jobs,
choose models, run post-checks or derive outcomes; ``model/case_outcomes.py``
turns an accepted reply into results.

The findings of both replies are STRIDE threat items. ``contract`` closes
the item of ``multi-repo-stride.schema.json`` with each reply's extension
fields, and the reviews pass the findings to ``validate_stride``, so the
evidence, trace and rating rules of the STRIDE step apply unchanged.
Candidates and every value derived from the repository belong in a job's
context; only plugin-owned catalog text enters its instructions.
"""

from __future__ import annotations

import copy
import hashlib
import posixpath
from functools import lru_cache
from typing import Any, Iterable, Mapping

from jsonschema import Draft202012Validator
from model import case_postchecks
from model.case_outcomes import is_documentation, load_catalog
from runtime.assessment_host import ExchangeError, Rejection

from contexts import multi_repo_analysis as analysis

INVESTIGATION = "test-case-investigation.schema.json"
OPEN_REVIEW = "open-review.schema.json"
CONTRACTS = (INVESTIGATION, OPEN_REVIEW)
#: Files one job may read beyond its starting files; each is listed in ``discovery_escapes``.
MAX_ESCAPE_FILES = 15

_STRIDE_ITEM_KEYS = frozenset({"type", "additionalProperties", "required", "properties"})
_COVERAGE_REASON = "Derived from the findings of a test case job."


def contract(name: str) -> dict:
    """The tool-host-compatible contract of a pilot reply, its findings closed over the STRIDE item."""
    if name not in CONTRACTS:
        raise ExchangeError("Unknown test case contract")
    return copy.deepcopy(_contract(name))


@lru_cache(maxsize=len(CONTRACTS))
def _contract(name: str) -> dict:
    schema = analysis.contract(name)
    findings = schema["properties"]["findings"]
    findings["items"] = _closed_item(findings["items"])
    Draft202012Validator.check_schema(schema)
    return schema


def _closed_item(item: Any) -> dict:
    """The STRIDE threat item with the reply's extension fields as one closed object.

    The plugin loader expands a reference with sibling keywords to ``allOf``,
    which a strict host drops, and the STRIDE item's closed properties would
    reject every extension field. A field the STRIDE item already defines
    cannot be redefined, so the shared fields keep one definition.
    """
    parts = item.get("allOf") if isinstance(item, dict) and set(item) == {"allOf"} else None
    if not isinstance(parts, list) or len(parts) != 2:
        raise ExchangeError("Test case findings must extend the STRIDE threat item")
    base, extension = copy.deepcopy(parts[0]), parts[1]
    if set(base) - _STRIDE_ITEM_KEYS or base.get("additionalProperties") is not False:
        raise ExchangeError("Test case findings must extend the STRIDE threat item")
    added = extension.get("properties") or {}
    if set(extension) - {"properties", "required"} or set(added) & set(base["properties"]):
        raise ExchangeError("Test case findings may only add fields to the STRIDE threat item")
    base["properties"].update(copy.deepcopy(added))
    base["required"] = [*base["required"], *(key for key in extension.get("required", []) if key in added)]
    return base


# --- instructions -------------------------------------------------------------


@lru_cache(maxsize=1)
def _catalog_cases() -> dict[str, dict]:
    return {case["id"]: case for case in load_catalog()["test_cases"]}


def catalog_instructions(case_ids: Iterable[str]) -> str:
    """The plugin-owned text of the named test cases, for an investigation's instructions.

    Each test case is rendered from the shipped catalog by its ID, never from a
    caller's copy, so candidates and repository-derived values cannot reach
    the instructions; they belong in the job's context. An unknown ID is an
    error. Post-checks are named only; a catalog ``pattern`` is not shown.
    """
    cases = _catalog_cases()
    blocks = []
    for case_id in case_ids:
        case = cases.get(case_id) if isinstance(case_id, str) else None
        if case is None:
            raise ValueError("unknown test case ID")
        checks = "; ".join(
            entry["check"] + (f" ({entry['guard']})" if entry.get("guard") else "") for entry in case["post"]
        )
        lines = [
            f"### {case['id']}: {case['title']}",
            # A goal test case names no CWE, so that none narrows the search.
            f"Aspect: {case['aspect']}. STRIDE: {', '.join(case['stride'])}."
            + (f" CWE: {', '.join(case['cwe'])}." if case["cwe"] else ""),
            f"Objective: {case['objective']}",
            f"Guidance: {case['guidance']}",
            f"Evidence for a finding: {case['evidence']['finding']}.",
            f"Evidence for a control: {case['evidence']['control']}.",
        ]
        if case["controls"]:
            lines.append(f"Matching controls: {', '.join(case['controls'])}.")
        if checks:
            lines.append(f"The controller checks your claims with: {checks}.")
        blocks.append("\n".join(lines))
    return "Test cases of this job (plugin-owned catalog text):\n\n" + "\n\n".join(blocks)


# --- controller-derived fields ------------------------------------------------


def investigation_normalizer(scope, component, aspect, identity, candidates):
    """Set what the controller knows instead of checking the model's copy (MR-17).

    Identity fields, the aspect and the admitted hash of each cited file come
    from the job. ``candidates`` maps each test case ID to the controller's
    pre-check candidates: a pre-check candidate keeps no model anchor and
    takes the controller's route. A finding title's location is the anchor's.
    """
    known = _fixed_candidates(candidates)
    hashes = analysis.controls_normalizer(scope, identity)

    def normalize(artifact):
        # Model anchors of pre-check candidates are dropped before the hashes are set.
        for case in artifact.get("test_cases") or []:
            for row in (case.get("candidates") or []) if isinstance(case, dict) else []:
                if isinstance(row, dict) and row.get("origin") == "pre-check":
                    row.pop("anchor", None)
                    route = known.get(row.get("candidate_id"), {}).get("route_id")
                    if route:
                        row["route_id"] = route
                    else:
                        row.pop("route_id", None)
        artifact = hashes(artifact)
        artifact.update(schema_version=1, component_id=component["id"], aspect=aspect)
        _locate_titles(artifact)
        return artifact

    normalize.version = "case-investigation-1"
    return normalize


def open_review_normalizer(scope, component, identity):
    """Identity fields, cited file hashes, located titles and every finding's empty ``test_case_ids``."""
    hashes = analysis.controls_normalizer(scope, identity)

    def normalize(artifact):
        artifact = hashes(artifact)
        artifact.update(schema_version=1, component_id=component["id"])
        for finding in artifact.get("findings") or []:
            if isinstance(finding, dict):
                finding["test_case_ids"] = []
        _locate_titles(artifact)
        return artifact

    normalize.version = "open-review-1"
    return normalize


def _fixed_candidates(candidates: Mapping[str, Iterable[Mapping]]) -> dict[str, Mapping]:
    return {row["candidate_id"]: row for rows in candidates.values() for row in rows}


def _locate_titles(artifact) -> None:
    """A title ends in its anchor's file and line when that fits, as in the STRIDE step (MR-17)."""
    for finding in artifact.get("findings") or []:
        title, anchor = (finding.get("title"), finding.get("evidence")) if isinstance(finding, dict) else (None, None)
        if not isinstance(title, str):
            continue
        base = analysis._TITLE_LOCATION.sub("", title).rstrip()  # noqa: SLF001
        if isinstance(anchor, dict) and isinstance(anchor.get("file"), str) and type(anchor.get("line")) is int:
            located = f"{base} ({posixpath.basename(anchor['file'])}:{anchor['line']})"
            finding["title"] = located if len(located) <= analysis.TITLE_MAX else base
        else:
            finding["title"] = base


# --- shared investigations ------------------------------------------------------


def combine_investigations(parts: list[dict]) -> dict:
    """One investigation of a component and aspect from the accepted replies of the jobs sharing its candidates.

    Each pre-check candidate is answered in exactly one job, and only the
    first job adds model candidates, so candidate IDs stay unique. Finding
    IDs repeat across jobs: each is rewritten with its job's position, with
    the candidates that name it, as the STRIDE step combines its jobs. A test
    case's proposed outcome combines its jobs' proposals by the outcome rules.
    The result is input for ``case_outcomes.investigation_results``, not a
    reply, and may exceed the reply contract.
    """
    if len(parts) == 1:
        return parts[0]
    combined = {**copy.deepcopy(parts[0]), "test_cases": [], "findings": [], "discovery_escapes": []}
    cases, proposals = {}, {}
    for index, part in enumerate(parts, 1):
        part = copy.deepcopy(part)
        # Hash the local identity instead of truncating arbitrary IDs.
        renamed = {
            row["local_id"]: f"part-{index}-" + hashlib.sha256(row["local_id"].encode()).hexdigest()[:16]
            for row in part["findings"]
        }
        for finding in part["findings"]:
            finding["local_id"] = renamed[finding["local_id"]]
        combined["findings"] += part["findings"]
        combined["discovery_escapes"] += part["discovery_escapes"]
        for case in part["test_cases"]:
            for row in case["candidates"]:
                row["finding_ids"] = [renamed[local_id] for local_id in row["finding_ids"]]
            case_id = case["test_case_id"]
            proposals.setdefault(case_id, []).append(case["proposed_outcome"])
            if case_id in cases:
                cases[case_id]["candidates"] += case["candidates"]
            else:
                cases[case_id] = case
                combined["test_cases"].append(case)
    for case_id, case in cases.items():
        case["proposed_outcome"] = _combined_proposal(proposals[case_id])
    return combined


def _combined_proposal(outcomes: list[str]) -> str:
    """The proposals of several jobs for one test case, in the order of ``component_outcome``'s rules."""
    if "finding" in outcomes:
        return "finding"
    if set(outcomes) == {"control"}:
        return "control"
    if {"control", "partial"} & set(outcomes):
        return "partial"
    if "undecidable" in outcomes:
        return "undecidable"
    return "no_finding"


# --- reviews ------------------------------------------------------------------


def validate_investigation(
    scope,
    component,
    neighborhood,
    flows,
    artifact,
    ranges,
    *,
    aspect: str,
    candidates: Mapping[str, Iterable[Mapping]],
    allowed_sources,
    starting_sources,
    facts: Mapping[str, Mapping] | None = None,
    boundaries=(),
    allowed_requirement_ids=frozenset(),
    adds_candidates: bool = True,
    answered_elsewhere: Mapping[str, Iterable[Mapping]] | None = None,
):
    """Accept an investigation only when it answers exactly its job and cites what it read.

    ``candidates`` maps each enabled, applicable test case of the job to the
    controller's pre-check candidates, so its keys are the test cases the
    reply must answer. ``allowed_sources`` are the files the job may cite,
    ``starting_sources`` the files served as starting points and preload,
    and ``facts`` the route facts per repository ID that a model candidate's
    route is checked against. When the candidates are shared among several
    jobs, only the job with ``adds_candidates`` may add model candidates,
    and never at a route or qualified anchor of the same test case that
    ``answered_elsewhere`` lists for the other jobs. Rejections name
    controller-known values or pattern-checked IDs, never model text.

    A control cited only from documentation is not rejected here; the outcome
    records it as undecidable.
    """
    if not Draft202012Validator(contract(INVESTIGATION)).is_valid(artifact):
        raise ExchangeError("Test case investigation violates its versioned contract")
    _validate_identity(scope, component, flows, artifact, "Test case investigation")
    if artifact["aspect"] != aspect:
        raise ExchangeError("Test case investigation changed its aspect")
    expected = {case_id: {row["candidate_id"] for row in rows} for case_id, rows in candidates.items()}
    answered = [row["test_case_id"] for row in artifact["test_cases"]]
    errors = [f"{case_id}: answer this test case of the job" for case_id in sorted(set(expected) - set(answered))]
    errors += [
        f"{case_id}: not a test case of this job; remove it" for case_id in sorted(set(answered) - set(expected))
    ]
    errors += [
        f"{case_id}: answer this test case once" for case_id in sorted(set(answered)) if answered.count(case_id) > 1
    ]
    if errors:
        raise Rejection("The investigation must answer exactly the job's test cases", errors)
    identifiers = [row["local_id"] for row in artifact["findings"]]
    if len(identifiers) != len(set(identifiers)):
        raise ExchangeError("Test case finding identities are not unique")
    errors = _candidate_errors(artifact, expected, component, facts or {}, adds_candidates, answered_elsewhere or {})
    errors += _link_errors(artifact)
    if errors:
        raise Rejection("The investigation's candidates and findings are inconsistent", errors)
    _validate_escapes(artifact, ranges, starting_sources, set(expected))
    analysis.validate_retrieved_sources(scope, artifact, ranges, allowed_sources)
    _validate_findings(
        scope, component, neighborhood, flows, artifact, ranges, allowed_sources, boundaries, allowed_requirement_ids
    )
    # Last, as in the STRIDE step: every earlier check passed, so only cited lines remain to correct (MR-2).
    cited = [
        {**({"anchor": row["anchor"]} if "anchor" in row else {}), "evidence": _code_evidence(row)}
        for case in artifact["test_cases"]
        for row in case["candidates"]
    ]
    analysis.validate_executable_evidence(
        scope, {"candidates": cited}, "Test case evidence does not cite an executable implementation"
    )


def validate_open_review(
    scope,
    component,
    neighborhood,
    flows,
    artifact,
    ranges,
    *,
    allowed_sources,
    starting_sources,
    boundaries=(),
    allowed_requirement_ids=frozenset(),
):
    """Accept an open review whose findings meet the STRIDE evidence rules and whose further reads are listed."""
    if not Draft202012Validator(contract(OPEN_REVIEW)).is_valid(artifact):
        raise ExchangeError("Open review violates its versioned contract")
    _validate_identity(scope, component, flows, artifact, "Open review")
    identifiers = [row["local_id"] for row in artifact["findings"]]
    if len(identifiers) != len(set(identifiers)):
        raise ExchangeError("Open review finding identities are not unique")
    _validate_escapes(artifact, ranges, starting_sources, None)
    analysis.validate_retrieved_sources(scope, artifact, ranges, allowed_sources)
    _validate_findings(
        scope, component, neighborhood, flows, artifact, ranges, allowed_sources, boundaries, allowed_requirement_ids
    )


def _validate_identity(scope, component, flows, artifact, label: str) -> None:
    if artifact["component_id"] != component["id"]:
        raise ExchangeError(f"{label} changed its component identity")
    if artifact["source_scope_sha256"] != scope.inventory()["scope_sha256"]:
        raise ExchangeError(f"{label} belongs to another source scope")
    if artifact["component_inventory_fingerprint"] != flows["component_inventory_fingerprint"]:
        raise ExchangeError(f"{label} refers to a stale component inventory")


def _candidate_errors(artifact, expected, component, facts, adds_candidates, elsewhere) -> list[str]:
    """Pre-check answers match the controller's set; model candidates stay in the component and its routes.

    A model candidate also belongs to the job that adds them, and not to a
    location another job of the component answers for the same test case.
    """
    own = analysis.source_selection([component])
    errors, seen = [], set()
    for case in artifact["test_cases"]:
        case_id = case["test_case_id"]
        answered = list(elsewhere.get(case_id, ()))
        routes = {row["route_id"] for row in answered if "route_id" in row}
        anchors = {(row["anchor"]["repository_id"], row["anchor"]["file"], row["anchor"]["line"]) for row in answered}
        pre = set()
        for row in case["candidates"]:
            candidate = row["candidate_id"]
            if candidate in seen:
                errors.append(f"{case_id}: candidate {candidate} is answered more than once in the reply")
            seen.add(candidate)
            if row["origin"] == "pre-check":
                pre.add(candidate)
                continue
            anchor = row["anchor"]
            if not adds_candidates:
                errors.append(
                    f"{case_id}: candidate {candidate}: only the first job of this component adds model "
                    "candidates; remove it"
                )
            elif (anchor["repository_id"], anchor["file"]) not in own:
                errors.append(
                    f"{case_id}: candidate {candidate} lies outside the component's own files; move or remove it"
                )
            elif row.get("route_id") in routes or (anchor["repository_id"], anchor["file"], anchor["line"]) in anchors:
                errors.append(
                    f"{case_id}: candidate {candidate} is a location that another job of this component answers; "
                    "remove it"
                )
            elif "route_id" in row:
                problem = _route_problem(row["route_id"], anchor, facts)
                if problem:
                    errors.append(
                        f"{case_id}: candidate {candidate}: {problem}; name a route the context lists at its "
                        "registration or handler, or omit route_id"
                    )
        errors += [
            f"{case_id}: answer pre-check candidate {candidate}" for candidate in sorted(expected[case_id] - pre)
        ]
        errors += [
            f"{case_id}: {candidate} is not a pre-check candidate of this test case; remove it"
            for candidate in sorted(pre - expected[case_id])
        ]
    return errors


def _route_problem(route_id: str, anchor: Mapping, facts: Mapping[str, Mapping]) -> str | None:
    """The fixed reason why a model candidate's route does not match its anchor, or None."""
    repository = facts.get(anchor["repository_id"])
    if not isinstance(repository, Mapping):
        return case_postchecks.UNKNOWN_ROUTE
    params = {"route_id": route_id, "anchor": {"file": anchor["file"], "line": anchor["line"]}}
    result = case_postchecks.run_check({"check": "route-registered"}, "weakness", params, repository)
    return None if result["result"] == case_postchecks.CONFIRMED else result["reason"]


def _link_errors(artifact) -> list[str]:
    """Findings and weakness candidates name each other, within the job's test cases."""
    cases = {case["test_case_id"] for case in artifact["test_cases"]}
    owners = {
        row["candidate_id"]: (case["test_case_id"], row)
        for case in artifact["test_cases"]
        for row in case["candidates"]
    }
    findings = {row["local_id"]: row for row in artifact["findings"]}
    errors = []
    for index, finding in enumerate(artifact["findings"]):
        if not set(finding["test_case_ids"]) <= cases:
            errors.append(f"findings[{index}] names a test case outside this job")
        for candidate in finding["candidate_ids"]:
            case_id, row = owners.get(candidate, (None, None))
            if row is None or row["status"] != "weakness" or case_id not in finding["test_case_ids"]:
                errors.append(f"findings[{index}] links {candidate}, which is no weakness candidate of its test cases")
            elif finding["local_id"] not in row["finding_ids"]:
                errors.append(f"findings[{index}] links {candidate}, whose finding_ids do not name the finding")
    for candidate, (case_id, row) in owners.items():
        for local_id in row["finding_ids"]:
            if candidate not in (findings.get(local_id) or {}).get("candidate_ids", ()):
                errors.append(f"{case_id}: candidate {candidate} names a finding that does not link it back")
    return list(dict.fromkeys(errors))


def _validate_escapes(artifact, ranges, starting_sources, cases: set[str] | None) -> None:
    """Every file served beyond the starting files is listed once, and only those, at most 15."""
    starting = set(starting_sources)
    further = sorted({row["path"] for row in ranges if (row["repository_id"], row["path"]) not in starting})
    errors, listed = [], {}
    for index, escape in enumerate(artifact["discovery_escapes"]):
        if cases is not None and escape["test_case_id"] not in cases:
            errors.append(f"discovery_escapes[{index}] names a test case outside this job")
        for path in escape["search_paths"]:
            if path in listed:
                errors.append(f"discovery_escapes[{index}] lists a file another escape already lists")
            listed.setdefault(path, index)
    if len(listed) > MAX_ESCAPE_FILES or len(further) > MAX_ESCAPE_FILES:
        errors.append(f"at most {MAX_ESCAPE_FILES} files may be read beyond the starting files")
    errors += [
        f"discovery_escapes[{index}] lists a file this job did not read beyond its starting files"
        for path, index in listed.items()
        if path not in further
    ]
    errors += [
        f"{path} was read beyond the starting files; list it in discovery_escapes"
        for path in further
        if path not in listed
    ]
    if errors:
        raise Rejection(
            "Discovery escapes do not match the files read beyond the starting files", list(dict.fromkeys(errors))
        )


def _validate_findings(
    scope, component, neighborhood, flows, artifact, ranges, allowed_sources, boundaries, requirement_ids
):
    """The STRIDE review of the reply's findings: evidence, ownership, traces, ratings and executable lines."""
    analysis.validate_stride(
        scope,
        component,
        neighborhood,
        flows,
        _stride_view(artifact, component),
        ranges,
        boundaries=boundaries,
        allowed_requirement_ids=requirement_ids,
        related=frozenset(allowed_sources) - analysis.source_selection(neighborhood),
    )


def _stride_view(artifact, component) -> dict:
    """The reply's findings as a STRIDE component artifact; evidence rows stay the reply's own objects."""
    threats = [
        {key: value for key, value in finding.items() if key not in ("test_case_ids", "candidate_ids")}
        for finding in artifact["findings"]
    ]
    coverage = []
    for category in analysis.STRIDE_CATEGORIES:
        ids = [threat["local_id"] for threat in threats if threat["stride"] == category]
        coverage.append(
            {
                "category": category,
                "disposition": "finding" if ids else "no-evidence",
                "finding_ids": ids,
                "reason": _COVERAGE_REASON,
            }
        )
    return {
        "schema_version": 2,
        "source_scope_sha256": artifact["source_scope_sha256"],
        "component_inventory_fingerprint": artifact["component_inventory_fingerprint"],
        "component_id": component["id"],
        "component_name": component["name"],
        "analyzed_at": "test-case-job",
        "partial": False,
        "skipped_categories": [],
        "coverage": coverage,
        "threats": threats,
    }


def _code_evidence(row: Mapping) -> list:
    """Evidence that must cite executable lines; a control's documentation rows are left to the outcome."""
    if row["status"] != "control":
        return list(row["evidence"])
    return [evidence for evidence in row["evidence"] if not is_documentation(evidence["file"])]
