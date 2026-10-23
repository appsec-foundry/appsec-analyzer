"""orchestrator/assessment_test_cases.py: the model-backed test case pilot of a full assessment (REQ-040).

When the scan profile selects pilot aspects, ``_assessment_stride`` decides
this phase's jobs before the survey (``plan_pilot``) and runs them after every
survey job is accepted and before the merge (``run_pilot``). For each
component and investigated aspect, the enabled test cases that apply get
their starting candidates from the deterministic facts of the component's
repository (``model/case_candidates.py``), and one optional
``test_case_investigator`` job answers them inside the STRIDE job's context
envelope. More candidates than one job takes are shared among several jobs,
each location in one of them, and their accepted replies are combined
(``contexts/case_analysis.combine_investigations``).
``model/case_outcomes.py`` turns the reply into one result per test case and
component. A failed or unaffordable job makes its candidates undecidable, so
the run continues.

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
INVESTIGATED_ASPECTS = ("AuthZ", "InputVal", "DataProt", "AI")
MULTI_REPOSITORY_REASON = "the pilot investigates only components of a single repository"
NO_CANDIDATE_REASON = "no test case of the aspect has a starting candidate in the component, so no model job ran"
_ADAPTATION = (
    "Answer the supplied test cases for the selected component and aspect. The context's "
    "test_case_candidates lists each test case's pre-check candidates; the controller serves each "
    "candidate's anchor and resolved handler lines, and the lines the supplied controls, flows and "
    "boundaries cite, in source_slices. readable_sources maps each repository_id to its permitted paths: "
    "read only exact pairs from it, in one read action. A route marked generated is registered by a REST resource "
    "generator at its anchor and handled by library code: judge it by the generator call, the data model it names, "
    "and the registrations for the same path among its handler lines. A candidate's sinks are the lines in its "
    "handler where fixed patterns found the mechanism its test case asks about; they are hints, and other paths "
    "count as well. When the context has candidate_jobs, other jobs answer the "
    "rest of the component's candidates: add model candidates only when adds_candidates is true, and never at a "
    "location that answered_elsewhere lists for the same test case."
)


def plan_pilot(scope, architecture, scanned, test_cases, *, progress) -> dict:
    """Decide the verification jobs before the survey runs, from deterministic inputs only.

    ``scanned`` holds the scanner findings per component. The jobs depend on
    the catalog, the architecture and the scanner findings, never on survey
    results, so the run names them before the survey and the live progress
    weighs them from the start instead of growing the phase afterwards.
    """
    catalog = case_outcomes.load_catalog()
    cases = {case["id"]: case for case in catalog["test_cases"]}
    disabled = {row["id"]: row["reason"] for row in test_cases["disable"]}
    aspects = [aspect for aspect in test_cases["aspects"] if aspect in INVESTIGATED_ASPECTS]
    deferred = [aspect for aspect in test_cases["aspects"] if aspect not in INVESTIGATED_ASPECTS]
    components = architecture["components"]["components"]
    findings_by_repository = _repository_findings(scope, scanned)
    facts = _repository_facts(scope, architecture, components, findings_by_repository) if aspects else {}

    entries = []
    for component in components:
        rid = component["repository_ids"][0] if len(component["repository_ids"]) == 1 else None
        for aspect in aspects:
            entry = {"component": component, "aspect": aspect, "fixed": {}, "precheck": {}}
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
            # A job without any candidate costs its full context; only a goal test case explores without one.
            if entry["precheck"] and not any(
                rows or cases[case_id].get("goal") for case_id, rows in entry["precheck"].items()
            ):
                for case_id in entry["precheck"]:
                    entry["fixed"][case_id] = _fixed(
                        cases[case_id], component["id"], "undecidable", NO_CANDIDATE_REASON
                    )
                entry["precheck"] = {}
            if entry["precheck"]:
                entry["jobs"] = case_candidates.batches(entry["precheck"])
            entries.append(entry)
    work = [(entry, number) for entry in entries if entry["precheck"] for number in range(1, len(entry["jobs"]) + 1)]
    worked = sorted({entry["aspect"] for entry, _ in work}, key=aspects.index)
    verified = list(dict.fromkeys(entry["component"]["id"] for entry, _ in work))
    if work:
        progress(
            f"Verify planned · {_count_components(len(verified))} for {', '.join(worked)} after the survey"
            f" · {_count_jobs(len(work))}"
        )
    return {
        "catalog": catalog,
        "cases": cases,
        "aspects": aspects,
        "deferred": deferred,
        "facts": facts,
        "entries": entries,
        "work": work,
        "worked": worked,
        "verified": verified,
    }


def run_pilot(
    scope,
    jobs,
    architecture,
    planned,
    envelopes,
    *,
    requirement_ids,
    instructions,
    concurrently,
    label,
    progress,
) -> dict:
    """Run the jobs ``plan_pilot`` decided; return the pilot's sidecar document.

    ``envelopes`` holds the STRIDE context envelope per component.
    ``instructions(role, adaptation)`` and ``concurrently(jobs, items, work)``
    are the controller's. The document holds the component results, the
    findings of accepted replies with ``TCF-`` IDs, and each component's
    candidates for its context artifact.
    """
    catalog, cases, aspects, facts = planned["catalog"], planned["cases"], planned["aspects"], planned["facts"]
    entries, work = planned["entries"], planned["work"]
    if planned["deferred"]:
        jobs.notes.append(
            f"test case aspects {', '.join(planned['deferred'])} are selected but not investigated yet; "
            f"this pilot investigates {', '.join(INVESTIGATED_ASPECTS)} only"
        )
    components = architecture["components"]["components"]
    owned = analysis.source_selection(components)
    verified = planned["verified"]
    if work:
        progress(_budget_statement(jobs, len(work), planned["worked"], len(verified)))
    # The console shows one step per component: each job names its component and its part of the component's jobs.
    parts = [[index for index, (entry, _) in enumerate(work) if entry["component"]["id"] == cid] for cid in verified]

    def investigate(position, item, view):
        entry, number = item
        component, aspect = entry["component"], entry["aspect"]
        rid = component["repository_ids"][0]
        share, count = entry["jobs"][number - 1], len(entry["jobs"])
        envelope = envelopes[component["id"]]
        unit = verified.index(component["id"])
        part = parts[unit].index(position - 1) + 1
        job = f"component {unit + 1}/{len(verified)}, part {part}/{len(parts[unit])}, {aspect}: {label(component)}"
        progress(f"Verifying {job}")
        context = {
            **envelope["context"],
            "aspect": aspect,
            "test_case_candidates": _context_candidates(share, rid, facts[rid]),
        }
        # Only the first of several jobs adds model candidates, and never where another job answers.
        elsewhere = _answered_elsewhere(entry["jobs"], number, rid) if count > 1 and number == 1 else {}
        if count > 1:
            context["candidate_jobs"] = {"job": number, "of": count, "adds_candidates": number == 1}
            if number == 1:
                context["candidate_jobs"]["answered_elsewhere"] = _locations(elsewhere, facts[rid])
        role_instructions = instructions(
            "test_case_investigator", _ADAPTATION + "\n\n" + case_analysis.catalog_instructions(share)
        )
        schema = case_analysis.contract(case_analysis.INVESTIGATION)
        limit = view.context_limit(role_instructions, schema)
        anchors = {(rid, row["anchor"]["file"]) for rows in share.values() for row in rows}
        # The job's context names its starting files, which the preload decides; keep room for one per window.
        longest = max((len(path) for _, path in envelope["job_allowed"]), default=0)
        reserve = (len(anchors) + MAX_PRELOAD_WINDOWS) * (longest + 64)
        preload = _preload(scope, context, share, rid, facts[rid], envelope, architecture, components, limit - reserve)
        starting = {(key[0], key[1]) for key in preload} | anchors
        context["starting_files"] = [{"repository_id": key[0], "path": key[1]} for key in sorted(starting)]
        identity = {key: context[key] for key in ("source_scope_sha256", "component_inventory_fingerprint")}
        # Files of no component, such as shared helpers, where a finding may anchor once the job read them.
        shared = frozenset(envelope["job_allowed"]) - owned
        selector = f"test-cases:{component['id']}:{aspect}" + (f":{number}/{count}" if count > 1 else "")
        artifact = view.execute(
            role="test_case_investigator",
            selector=selector,
            instructions=role_instructions,
            context=context,
            schema=schema,
            allowed_sources=envelope["job_allowed"],
            normalize=case_analysis.investigation_normalizer(scope, component, aspect, identity, share),
            salvage=case_analysis.investigation_salvage,
            preload=preload,
            validate=lambda artifact, ranges: case_analysis.validate_investigation(
                scope,
                component,
                envelope["neighborhood"],
                architecture["data_flows"],
                artifact,
                ranges,
                aspect=aspect,
                candidates=share,
                allowed_sources=envelope["job_allowed"],
                starting_sources=starting,
                facts={rid: facts[rid]},
                boundaries=envelope["adjacent"],
                allowed_requirement_ids=requirement_ids,
                adds_candidates=number == 1,
                answered_elsewhere=elsewhere,
                shared_files=shared,
            ),
            # The candidates of a replaced job record undecidable (OR-39).
            on_failure=lambda reason: {"replaced": True},
        )
        if artifact.get("replaced"):
            gap = next(row for row in view.gaps if row["selector"] == selector)
            cause = "budget" if gap.get("budget") else "failure"
            progress(f"Finished verifying {job} · no result ({cause})")
            return {"cause": cause}
        if artifact.get("dropped_findings"):
            view.notes.append(
                f"verification job {selector} dropped {len(artifact['dropped_findings'])} findings that still broke "
                "an evidence, trace or rating rule after the last correction; their candidates are undecidable"
            )
        progress(f"Finished verifying {job}")
        return {"reply": artifact}

    answered = {}
    for (entry, number), answer in zip(work, concurrently(jobs, work, investigate) if work else [], strict=True):
        answered.setdefault(id(entry), []).append((entry["jobs"][number - 1], answer))
    results, findings, candidates = [], [], {}
    for entry in entries:
        component = entry["component"]
        parts = answered.get(id(entry), [])
        replies = [answer["reply"] for _, answer in parts if "reply" in answer]
        derived = {}
        if replies:
            rid = component["repository_ids"][0]
            reply = case_analysis.combine_investigations(replies)
            outcome = case_outcomes.investigation_results(
                reply,
                component["id"],
                precheck=entry["precheck"],
                facts=facts[rid],
                repository_id=rid,
                catalog=catalog,
                replaced={
                    row["candidate_id"]: answer["cause"]
                    for share, answer in parts
                    if "cause" in answer
                    for rows in share.values()
                    for row in rows
                },
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
        # A test case that no accepted job answered takes the cause of its first replaced job.
        for share, answer in parts:
            for case_id in share:
                if "cause" in answer and case_id not in derived:
                    derived[case_id] = case_outcomes.replacement_result(
                        cases[case_id], component["id"], answer["cause"], unexamined=len(entry["precheck"][case_id])
                    )
        results += [entry["fixed"].get(case["id"]) or derived[case["id"]] for case in entry["cases"]]
        if entry["precheck"]:
            rid = component["repository_ids"][0]
            candidates.setdefault(component["id"], []).extend(
                {**row, "aspect": entry["aspect"]} for row in _context_candidates(entry["precheck"], rid, facts[rid])
            )
    # REQ-040: an aspect whose jobs the budget cut short is incomplete, and the result says so.
    incomplete = [
        aspect
        for aspect in aspects
        if any(
            answer.get("cause") == "budget"
            for entry in entries
            if entry["aspect"] == aspect
            for _, answer in answered.get(id(entry), [])
        )
    ]
    progress(
        "Verify done · "
        + (f"{', '.join(aspects)} · " if aspects else "")
        + f"{len(results)} results, {len(findings)} findings"
        + (f"; incomplete for {', '.join(incomplete)} because the budget ended" if incomplete else "")
    )
    return {
        "schema_version": 1,
        "aspects": aspects,
        "incomplete_aspects": incomplete,
        "results": results,
        "findings": findings,
        "candidates": candidates,
    }


def _budget_statement(jobs, count: int, aspects: list[str], components: int) -> str:
    """Whether the remaining budget covers every verification job, said before the first one runs (REQ-040).

    Until a verification job is accepted, the reserve of a survey job stands in for one: both carry the
    component's context. A run that cannot cover them all keeps going; the budget stops the jobs it cannot
    pay, and their aspects are marked incomplete. The job count closes the line for the console, which
    weighs the jobs and shows the components."""
    subject = f"Verify start · {_count_components(components)} for {', '.join(aspects)}"
    budget = jobs.budget
    if budget.subscription:
        return f"{subject} · the run's call and time limits apply · {_count_jobs(count)}"
    needed = count * budget.job_usd("test_case_investigator", "stride_analyzer")
    available = budget.available_usd()
    if needed <= available:
        return f"{subject} · about USD {needed:.2f}, USD {available:.2f} of the budget left · {_count_jobs(count)}"
    jobs.notes.append(
        f"verification needs about USD {needed:.2f} for {count} jobs, but USD {available:.2f} remained; "
        "aspects whose jobs the budget stops are marked incomplete"
    )
    return (
        f"{subject} · about USD {needed:.2f}, but only USD {available:.2f} of the budget left; "
        f"an aspect that cannot finish is marked incomplete · {_count_jobs(count)}"
    )


def _count_jobs(count: int) -> str:
    return f"{count} {'job' if count == 1 else 'jobs'}"


def _count_components(count: int) -> str:
    return f"{count} {'component' if count == 1 else 'components'}"


def write_workspace(document: dict, workspace, names) -> None:
    """Write the pilot sidecar the model builder reads and each component's candidate context artifact."""
    ws.write_json(
        workspace / case_outcomes.PILOT_SIDECAR,
        ws.project_document(
            {
                key: document[key]
                for key in ("schema_version", "aspects", "incomplete_aspects", "results", "findings")
                if key in document
            },
            names,
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


def _context_candidates(precheck, rid: str, facts) -> list[dict]:
    """Candidates per test case as context data: qualified anchors, and each route's method and path."""
    listed = []
    for case_id, rows in precheck.items():
        candidates = []
        for row in rows:
            candidate = {**row, "anchor": {"repository_id": rid, **row["anchor"]}}
            if "route_id" in row:
                candidate["route"] = _route(facts, row["route_id"])
            candidates.append(candidate)
        listed.append({"test_case_id": case_id, "candidates": candidates})
    return listed


def _answered_elsewhere(shares, number: int, rid: str) -> dict[str, list[dict]]:
    """Per test case, the pre-check candidates that the other jobs answer, with qualified anchors."""
    found: dict[str, list[dict]] = {}
    for other, share in enumerate(shares, 1):
        if other == number:
            continue
        for case_id, rows in share.items():
            found.setdefault(case_id, []).extend(
                {**row, "anchor": {"repository_id": rid, **row["anchor"]}} for row in rows
            )
    return found


def _locations(elsewhere, facts) -> list[dict]:
    """The locations of ``_answered_elsewhere`` as context data, without candidate IDs to answer."""
    return [
        {
            "test_case_id": case_id,
            "locations": [
                {"anchor": row["anchor"], **({"route": _route(facts, row["route_id"])} if "route_id" in row else {})}
                for row in rows
            ],
        }
        for case_id, rows in elsewhere.items()
    ]


def _route(facts, route_id: str) -> dict:
    route = facts["routes"][route_id]
    return {"method": route["method"], "path": route["path"], **({"generated": True} if route["generated"] else {})}


def _preload(scope, context, precheck, rid, facts, envelope, architecture, components, limit) -> list[tuple]:
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
    for row in (row for rows in precheck.values() for row in rows):
        anchor = {"repository_id": rid, **row["anchor"]}
        anchors.append(anchor)
        route = facts["routes"].get(row.get("route_id")) or {}
        lines += [{"repository_id": rid, "file": path, "line": first} for path, first, _ in route.get("chain", [])]
        # A sink can lie far into a long handler.
        lines += [{"repository_id": rid, **sink} for sink in row.get("sinks", [])]
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
