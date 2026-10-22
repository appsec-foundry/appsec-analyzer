"""orchestrator/assessment_test_cases.py: the model-backed test case pilot of a full assessment (REQ-040).

When the scan profile selects pilot aspects, ``_assessment_stride`` runs this
phase after every STRIDE job is accepted and before the merge. For each
component and investigated aspect, the enabled test cases that apply get
their starting candidates from the deterministic facts of the component's
repository (``model/case_candidates.py``), and one optional
``test_case_investigator`` job answers them inside the STRIDE job's context
envelope. ``model/case_outcomes.py`` turns an accepted reply into one result
per test case and component. A failed or unaffordable job becomes an
undecidable result, so the run continues.

The phase changes no STRIDE request and merges nothing into the threats: its
findings stay a separate list until the pilot decides how to merge them.
Candidates and every other repository-derived value reach a job only in its
context, never in its instructions (REQ-031). The controller supplies the job
runner, the role instructions and the component pool.
"""

from __future__ import annotations

from contexts import case_analysis
from contexts import multi_repo_analysis as analysis
from model import case_candidates, case_outcomes
from runtime.assessment_host import MAX_PRELOAD_WINDOWS, preload_room
from shared.assessment_sources import source_rows

from orchestrator import assessment_workspace as ws

#: Aspects this step investigates; a profile may select further pilot aspects.
INVESTIGATED_ASPECTS = ("AuthZ",)
MULTI_REPOSITORY_REASON = "the pilot investigates only components of a single repository"
_ADAPTATION = (
    "Answer the supplied test cases for the selected component and aspect. The context's "
    "test_case_candidates lists each test case's pre-check candidates; the controller serves each "
    "candidate's anchor and resolved handler lines, and the lines the supplied controls, flows and "
    "boundaries cite, in source_slices. readable_sources maps each repository_id to its permitted paths: "
    "read only exact pairs from it, in one read action."
)


def run_pilot(
    scope,
    jobs,
    architecture,
    scanned,
    test_cases,
    envelopes,
    *,
    requirement_ids,
    instructions,
    concurrently,
    label,
    progress,
) -> dict:
    """Investigate the selected aspects per component; return the pilot's sidecar document.

    ``scanned`` holds the scanner findings per component and ``envelopes`` the
    STRIDE context envelope per component. ``instructions(role, adaptation)``
    and ``concurrently(jobs, items, work)`` are the controller's. The document
    holds the component results, the findings of accepted replies with
    ``TCF-`` IDs, and each component's candidates for its context artifact.
    """
    catalog = case_outcomes.load_catalog()
    cases = {case["id"]: case for case in catalog["test_cases"]}
    disabled = {row["id"]: row["reason"] for row in test_cases["disable"]}
    aspects = [aspect for aspect in test_cases["aspects"] if aspect in INVESTIGATED_ASPECTS]
    deferred = [aspect for aspect in test_cases["aspects"] if aspect not in INVESTIGATED_ASPECTS]
    if deferred:
        jobs.notes.append(
            f"test case aspects {', '.join(deferred)} are selected but not investigated yet; "
            f"this pilot investigates {', '.join(INVESTIGATED_ASPECTS)} only"
        )
    components = architecture["components"]["components"]
    findings_by_repository = _repository_findings(scope, scanned)
    facts = _repository_facts(scope, architecture, components, findings_by_repository) if aspects else {}

    entries = []
    for component in components:
        rid = component["repository_ids"][0] if len(component["repository_ids"]) == 1 else None
        for aspect in aspects:
            entry = {"component": component, "aspect": aspect, "fixed": {}, "precheck": {}, "overflow": {}}
            entry["cases"] = [
                case for case in catalog["test_cases"] if case["aspect"] == aspect and case["mode"] != "rules"
            ]
            for case in entry["cases"]:
                if case["id"] in disabled:
                    entry["fixed"][case["id"]] = _fixed(case, component["id"], "disabled", disabled[case["id"]])
                    continue
                if rid is None:
                    entry["fixed"][case["id"]] = _fixed(case, component["id"], "undecidable", MULTI_REPOSITORY_REASON)
                    continue
                applies, reason = case_candidates.applies(case, facts[rid], component["id"])
                if not applies:
                    entry["fixed"][case["id"]] = _fixed(case, component["id"], "not_applicable", reason)
                    continue
                found = case_candidates.starting_candidates(
                    case, component["id"], facts[rid], findings_by_repository[rid]
                )
                entry["precheck"][case["id"]] = found["candidates"]
                entry["overflow"][case["id"]] = found["overflow"]
            if entry["precheck"]:
                entry["candidates"] = _context_candidates(entry, rid, facts[rid])
            entries.append(entry)
    work = [entry for entry in entries if entry["precheck"]]

    def investigate(position, entry, view):
        component, aspect = entry["component"], entry["aspect"]
        rid = component["repository_ids"][0]
        envelope = envelopes[component["id"]]
        progress(f"Investigating test cases: {label(component)} ({aspect}, {position}/{len(work)})")
        context = {**envelope["context"], "aspect": aspect, "test_case_candidates": entry["candidates"]}
        role_instructions = instructions(
            "test_case_investigator", _ADAPTATION + "\n\n" + case_analysis.catalog_instructions(entry["precheck"])
        )
        schema = case_analysis.contract(case_analysis.INVESTIGATION)
        limit = view.context_limit(role_instructions, schema)
        preload = _preload(scope, context, entry, rid, facts[rid], envelope, architecture, components, limit)
        starting = {(key[0], key[1]) for key in preload} | {
            (rid, row["anchor"]["file"]) for rows in entry["precheck"].values() for row in rows
        }
        identity = {key: context[key] for key in ("source_scope_sha256", "component_inventory_fingerprint")}
        selector = f"test-cases:{component['id']}:{aspect}"
        artifact = view.execute(
            role="test_case_investigator",
            selector=selector,
            instructions=role_instructions,
            context=context,
            schema=schema,
            allowed_sources=envelope["job_allowed"],
            normalize=case_analysis.investigation_normalizer(scope, component, aspect, identity, entry["precheck"]),
            preload=preload,
            validate=lambda artifact, ranges: case_analysis.validate_investigation(
                scope,
                component,
                envelope["neighborhood"],
                architecture["data_flows"],
                artifact,
                ranges,
                aspect=aspect,
                candidates=entry["precheck"],
                allowed_sources=envelope["job_allowed"],
                starting_sources=starting,
                facts={rid: facts[rid]},
                boundaries=envelope["adjacent"],
                allowed_requirement_ids=requirement_ids,
            ),
            # The test cases of a replaced job record undecidable (OR-39).
            on_failure=lambda reason: {"replaced": True},
        )
        if artifact.get("replaced"):
            gap = next(row for row in view.gaps if row["selector"] == selector)
            return {"cause": "budget" if gap.get("budget") else "failure"}
        return {"reply": artifact}

    answers = dict(zip(map(id, work), concurrently(jobs, work, investigate) if work else [], strict=True))
    results, findings, candidates = [], [], {}
    for entry in entries:
        component = entry["component"]
        answer = answers.get(id(entry), {})
        derived = {}
        if "reply" in answer:
            rid = component["repository_ids"][0]
            reply = answer["reply"]
            outcome = case_outcomes.investigation_results(
                reply,
                component["id"],
                precheck=entry["precheck"],
                overflow=entry["overflow"],
                facts=facts[rid],
                repository_id=rid,
                catalog=catalog,
            )
            # Reply-local IDs repeat across jobs, so each kept finding gets a run-wide TCF- ID.
            local = {}
            for finding in reply["findings"]:
                if finding["local_id"] not in outcome["dropped_finding_ids"]:
                    local[finding["local_id"]] = f"TCF-{len(findings) + 1:03d}"
                    findings.append(_finding(finding, local[finding["local_id"]], component["id"], entry["aspect"]))
            for row in outcome["results"]:
                row["finding_ids"] = [local[value] for value in row["finding_ids"]]
                derived[row["test_case_id"]] = row
        elif "cause" in answer:
            for case_id, rows in entry["precheck"].items():
                derived[case_id] = case_outcomes.replacement_result(
                    cases[case_id], component["id"], answer["cause"], unexamined=len(rows) + entry["overflow"][case_id]
                )
        results += [entry["fixed"].get(case["id"]) or derived[case["id"]] for case in entry["cases"]]
        if entry["precheck"]:
            candidates.setdefault(component["id"], []).extend(
                {**row, "aspect": entry["aspect"]} for row in entry["candidates"]
            )
    progress(f"Test case pilot: {len(results)} results, {len(findings)} findings")
    return {"schema_version": 1, "aspects": aspects, "results": results, "findings": findings, "candidates": candidates}


def write_workspace(document: dict, workspace, names) -> None:
    """Write the pilot sidecar the model builder reads and each component's candidate context artifact."""
    ws.write_json(
        workspace / case_outcomes.PILOT_SIDECAR,
        ws.project_document(
            {key: document[key] for key in ("schema_version", "aspects", "results", "findings")}, names
        ),
    )
    for component_id, rows in document["candidates"].items():
        path = workspace / ".dispatch-context" / component_id / "test-case-candidates.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        ws.write_json(
            path, ws.project_document({"schema_version": 1, "component_id": component_id, "test_cases": rows}, names)
        )


def _repository_findings(scope, scanned) -> dict[str, list[dict]]:
    found: dict[str, list[dict]] = {repo.repository_id: [] for repo in scope.repositories}
    for rows in scanned.values():
        for threat in rows:
            found[threat["evidence"]["repository_id"]].append(threat)
    return found


def _repository_facts(scope, architecture, components, findings) -> dict[str, dict]:
    """Route facts of each repository snapshot, read once, with the files each component owns there."""
    facts = {}
    for repo in sorted(scope.repositories, key=lambda row: row.repository_id):
        rid = repo.repository_id
        owned = {
            row["id"]: [p["path"] for p in row["paths"] if p["repository_id"] == rid]
            for row in components
            if rid in row["repository_ids"]
        }
        with scope.scanner_snapshot(rid) as root:
            facts[rid] = case_candidates.route_facts(
                root, architecture["route_inventories"][rid], findings[rid], components=owned
            )
    return facts


def _fixed(case, component_id: str, outcome: str, reason: str) -> dict:
    """The result of a test case that no investigation examined: disabled, not applicable or out of reach."""
    row = case_outcomes.component_outcome(case, component_id, [])
    row.update(outcome=outcome, reason=reason, evidence_basis="deterministic")
    return row


def _context_candidates(entry, rid: str, facts) -> list[dict]:
    """The job's candidates as context data: qualified anchors, and each route's method and path."""
    listed = []
    for case_id, rows in entry["precheck"].items():
        candidates = []
        for row in rows:
            candidate = {**row, "anchor": {"repository_id": rid, **row["anchor"]}}
            if "route_id" in row:
                route = facts["routes"][row["route_id"]]
                candidate["route"] = {"method": route["method"], "path": route["path"]}
            candidates.append(candidate)
        listed.append({"test_case_id": case_id, "candidates": candidates, "unexamined": entry["overflow"][case_id]})
    return listed


def _preload(scope, context, entry, rid, facts, envelope, architecture, components, limit) -> list[tuple]:
    """Preload as the STRIDE job does: the context's cited lines, guards, candidate windows, then helpers.

    The definitions of the middlewares the candidates' routes run come before
    the candidates: one guard decides many routes, and a guard the job cannot
    read leaves its routes undecidable. The candidates' anchors and resolved
    handler chains take the room left; earlier guard registrations and the
    direct helpers their files import fill the rest.
    """
    room = preload_room(context, max_context_bytes=limit)
    context_preload = analysis.evidence_preload(
        scope,
        source_rows([context["existing_controls"], envelope["incident"], envelope["adjacent"]]),
        envelope["allowed"],
        room=room // 4,
        max_windows=MAX_PRELOAD_WINDOWS // 4,
        before=10,
        after=30,
    )
    inventory = {row.get("route_id"): row for row in architecture["route_inventories"][rid].get("routes", [])}
    wares = architecture.get("route_middleware", {}).get(rid, {})
    anchors, lines, guards, targets = [], [], [], []
    for row in (row for rows in entry["precheck"].values() for row in rows):
        anchor = {"repository_id": rid, **row["anchor"]}
        anchors.append(anchor)
        route = facts["routes"].get(row.get("route_id")) or {}
        lines += [{"repository_id": rid, "file": path, "line": first} for path, first, _ in route.get("chain", [])]
        guards += [
            {"repository_id": rid, "file": path, "line": start} for path, start, _ in wares.get(row.get("route_id"), [])
        ]
        registered = (inventory.get(row.get("route_id")) or {}).get("guard_lines") or []
        targets.append(
            {"evidence": anchor, "guard_lines": [[rid, route.get("handler_file"), line] for line in registered]}
        )
    served = list(context_preload)
    # Middleware definitions get a quarter of what is left, the candidates the rest.
    for rows, share, before, after in (
        (guards, 4, 0, analysis.MAX_MIDDLEWARE_LINES - 1),
        ([*anchors, *lines], 1, 10, 40),
    ):
        served += [
            key
            for key in analysis.evidence_preload(
                scope,
                rows,
                envelope["job_allowed"],
                room=(room - analysis.served_bytes(scope, served)) // share,
                max_windows=(MAX_PRELOAD_WINDOWS - len(served)) // share,
                before=before,
                after=after,
            )
            if key not in served
        ]
    return analysis.supporting_preload(
        scope,
        targets,
        served,
        envelope["job_allowed"],
        context=context,
        component_sources=analysis.source_selection(components),
        max_context_bytes=limit,
    )


def _finding(finding: dict, finding_id: str, component_id: str, aspect: str) -> dict:
    """An accepted pilot finding for the model: the reply's STRIDE item under its model ID."""
    row = {"id": finding_id, "component_id": component_id, "aspect": aspect, "test_case_ids": finding["test_case_ids"]}
    row.update(
        (key, value) for key, value in finding.items() if key not in ("local_id", "candidate_ids", "test_case_ids")
    )
    return row
