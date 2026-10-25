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

import threading
from collections import Counter

from contexts import case_analysis
from contexts import multi_repo_analysis as analysis
from model import case_candidates, case_outcomes
from runtime.assessment_host import MAX_PRELOAD_WINDOWS, preload_room
from shared.assessment_sources import source_rows

from orchestrator import assessment_workspace as ws

#: Aspects this step investigates; a profile may select further pilot aspects.
INVESTIGATED_ASPECTS = ("AuthN", "AuthNRoutes", "AuthZ", "InputVal", "DataProt", "AI")
MULTI_REPOSITORY_REASON = "the pilot investigates only components of a single repository"
NO_CANDIDATE_REASON = "no test case of the aspect has a starting candidate in the component, so no model job ran"
#: Lines served from where a generated route's data model is defined: the fields its request body can set follow.
MAX_MODEL_LINES = 120
_ADAPTATION = (
    "Answer exactly the test cases that test_case_candidates lists, for the selected component and aspect; the "
    "catalog text below also describes the test cases the component's other jobs answer. The context's "
    "test_case_candidates lists each test case's pre-check candidates; the controller serves each "
    "candidate's anchor and resolved handler lines, and the lines the supplied controls, flows and "
    "boundaries cite, in source_slices. readable_sources maps each repository_id to its permitted paths, grouped by "
    "the id of the listed component that owns them, other for paths of no listed component: read only exact "
    "pairs from it, in one read action. A route marked generated is registered by a REST resource "
    "generator at its anchor and handled by library code: judge it by the generator call, the data model it names, "
    "and the registrations for the same path among its handler lines. A candidate's sinks are the lines in its "
    "handler where fixed patterns found the mechanism its test case asks about; they are hints, and other paths "
    "count as well. A candidate inside a handler lists in reached_by the routes whose handlers reach it, each with "
    "registered_at: the lines where the route and the guards that run before its handler are registered. Read "
    "them before you judge the candidate; those guards decide it as well. When the context has candidate_jobs, other jobs answer the "
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
    entries, work = planned["entries"], _first_jobs_first(planned["work"])
    if planned["deferred"]:
        jobs.notes.append(
            f"test case aspects {', '.join(planned['deferred'])} are selected but not investigated yet; "
            f"this pilot investigates {', '.join(INVESTIGATED_ASPECTS)} only"
        )
    components = architecture["components"]["components"]
    owned = analysis.source_selection(components)
    verified = planned["verified"]
    if work:
        reused = sum(jobs.has_accepted("test_case_investigator", _selector(*item)) for item in work)
        progress(_budget_statement(jobs, len(work), planned["worked"], len(verified), reused=reused))
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
            "test_case_investigator", _ADAPTATION + "\n\n" + case_analysis.catalog_instructions(_entry_cases(entry))
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
        selector = _selector(entry, number)
        exchanged = view.exchange(
            role="test_case_investigator",
            selector=selector,
            instructions=role_instructions,
            context=context,
            schema=schema,
            allowed_sources=envelope["job_allowed"],
            normalize=case_analysis.investigation_normalizer(scope, component, aspect, identity, share),
            salvage=case_analysis.investigation_salvage,
            preload=preload,
            # The component's context and the aspect are the same in every job of the entry.
            shared_context_keys=len(envelope["context"]) + 1,
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
        artifact = exchanged.artifact
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
        # The view holds this one job, so the console can mark a component whose every job was reused.
        progress(f"Finished verifying {job}" + (" · reused" if view.reused and not view.ran else ""))
        return {"reply": artifact, "usd": exchanged.usd}

    answered = {}
    dispatched = concurrently(jobs, work, _after_first_jobs(work, investigate)) if work else []
    for (entry, number), answer in zip(work, dispatched, strict=True):
        answered.setdefault(id(entry), []).append((entry["jobs"][number - 1], answer))
    results, findings, candidates = [], [], {}
    usd = {}
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
                    row = _finding(finding, local[finding["local_id"]], component["id"], entry["aspect"])
                    # The merge keeps findings on different routes apart and scores only checked ones (REQ-040).
                    findings.append({**row, **outcome["findings"][finding["local_id"]]})
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
        usd[entry["aspect"]] = usd.get(entry["aspect"], 0.0) + sum(answer.get("usd") or 0.0 for _, answer in parts)
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
    # What each aspect found and cost, so a reader can weigh one against the other, and what its items showed;
    # a replaced job's cost is in the run's total only. The console adds the step's duration and cost.
    progress(
        "Verify done"
        + ("" if aspects else " · no aspect verified")
        + (f" · incomplete for {', '.join(incomplete)} because the budget ended" if incomplete else "")
    )
    for aspect in aspects:
        progress(aspect_line(aspect, results, findings, None if jobs.budget.subscription else usd.get(aspect, 0.0)))
    return {
        "schema_version": 1,
        "aspects": aspects,
        "incomplete_aspects": incomplete,
        "results": results,
        "findings": findings,
        "candidates": candidates,
    }


def _entry_cases(entry) -> list[str]:
    """Every test case the jobs of one component and aspect answer, each once, in job order.

    Every job of the entry gets the catalog text of all of them, so the jobs'
    prompts are the same up to the end of the shared component context, and
    the later jobs read that start from the host's prompt cache.
    """
    return list(dict.fromkeys(case_id for share in entry["jobs"] for case_id in share))


def _first_jobs_first(work: list) -> list:
    """The first job of every entry before all later jobs, in their planned order otherwise."""
    return [item for item in work if item[1] == 1] + [item for item in work if item[1] > 1]


def _after_first_jobs(work: list, investigate):
    """`investigate` where a later job of an entry starts only once the entry's first job has ended.

    The first job writes the entry's shared context into the prompt cache; a
    later job started before that could not read it and would write it again.
    The pool takes jobs in order and `_first_jobs_first` puts the first jobs
    ahead, so the first job a later job waits for is already running.
    """
    ended = {id(entry): threading.Event() for entry, _ in work}

    def run(position, item, view):
        entry, number = item
        if number > 1:
            ended[id(entry)].wait()
        try:
            return investigate(position, item, view)
        finally:
            if number == 1:
                ended[id(entry)].set()

    return run


def _selector(entry, number: int) -> str:
    count = len(entry["jobs"])
    return f"test-cases:{entry['component']['id']}:{entry['aspect']}" + (f":{number}/{count}" if count > 1 else "")


def _budget_statement(jobs, count: int, aspects: list[str], components: int, *, reused: int = 0) -> str:
    """Whether the remaining budget covers every verification job, said before the first one runs (REQ-040).

    Until a verification job is accepted, the reserve of a survey job stands in for one: both carry the
    component's context. The ``reused`` jobs have an accepted result of an earlier attempt and need no new
    call, so they stay out of the estimate. A run that cannot cover them all keeps going; the budget stops
    the jobs it cannot pay, and their aspects are marked incomplete. The job count closes the line for the
    console, which weighs the jobs and shows the components."""
    subject = f"Verify start · {_count_components(components)} · {', '.join(aspects)}"
    budget = jobs.budget
    if reused >= count:
        return f"{subject} · reuses accepted results, no model calls expected · {_count_jobs(count)}"
    if budget.subscription:
        return f"{subject} · the run's call and time limits apply · {_count_jobs(count)}"
    needed = (count - reused) * budget.job_usd("test_case_investigator", "stride_analyzer")
    available = budget.available_usd()
    if needed <= available:
        return f"{subject} · ≈ USD {needed:.2f}, USD {available:.2f} of the budget left · {_count_jobs(count)}"
    jobs.notes.append(
        f"verification needs about USD {needed:.2f} for {count - reused} jobs, but USD {available:.2f} remained; "
        "aspects whose jobs the budget stops are marked incomplete"
    )
    return (
        f"{subject} · ≈ USD {needed:.2f}, but only USD {available:.2f} of the budget left; "
        f"an aspect that cannot finish is marked incomplete · {_count_jobs(count)}"
    )


def survey_line(documents, reviews) -> str:
    """What the survey found, said when it ends and verification starts (REQ-040).

    It counts the survey's findings before the merge, as the merge line does, and names those the evidence
    review refuted. The console adds the survey's duration and cost.
    """
    found = refuted = 0
    for document, review in zip(documents, reviews, strict=True):
        verdicts = {row["local_id"]: row["verdict"] for row in review["decisions"]}
        found += len(document["threats"])
        refuted += sum(1 for threat in document["threats"] if verdicts.get(threat.get("local_id")) == "refuted")
    return (
        "Survey done · " + _count(found, "finding") + (f", {refuted} refuted by the evidence review" if refuted else "")
    )


# Outcome -> the words of an aspect's verification line, in the completion summary's order.
_OUTCOME_WORDS = (
    ("finding", "with a finding", "with findings"),
    ("control", "control", "controls"),
    ("partial", "partial", "partial"),
    ("no_finding", "no finding", "no finding"),
    ("undecidable", "undecidable", "undecidable"),
    ("not_applicable", "not applicable", "not applicable"),
    ("disabled", "disabled", "disabled"),
)


def aspect_line(aspect: str, results, findings, usd) -> str:
    """What verification of one aspect found and cost, and what each of its items showed per component (REQ-040).

    The findings are the aspect's TCF- findings. The outcomes count one result per item and component, so
    they add up to the items times the components. ``usd`` is None without monetary accounting.
    """
    rows = [row for row in results if row.get("aspect") == aspect]
    counts = Counter(row["outcome"] for row in rows)
    outcomes = ", ".join(
        f"{counts[key]} {singular if counts[key] == 1 else plural}"
        for key, singular, plural in _OUTCOME_WORDS
        if counts.get(key)
    )
    items = _count(len({row["test_case_id"] for row in rows}), "item")
    components = _count_components(len({row["component_id"] for row in rows}))
    return (
        f"{aspect} · {_count(sum(1 for row in findings if row['aspect'] == aspect), 'finding')}"
        + ("" if usd is None else f" · ≈ USD {usd:.2f}")
        + f" · {items} in {components}"
        + (f": {outcomes}" if outcomes else "")
    )


def method_lines(threats, aspects, catalog) -> list[str]:
    """For each verified aspect, how many findings both methods and only one method found (REQ-040).

    Reads the model after the merge made each verification finding part of the finding it repeats, so the
    counts are the report's findings: one with a ``verification`` block holds verification findings, its
    ``found_by`` says whether the survey found it too, and a survey finding at a verified control is
    contradicted. A finding counts for an aspect when one of its verification items belongs to it, and a
    finding of the survey alone when its CWE is one of the aspect's verification items, so one finding can
    count for several aspects.
    """
    items = {case["id"]: case["aspect"] for case in catalog["test_cases"]}
    lines = []
    for aspect in aspects:
        cwes = aspect_cwes(catalog, aspect)
        verified = [
            row
            for row in threats
            if aspect in {items.get(case) for case in (row.get("verification") or {}).get("test_case_ids") or []}
        ]
        both = sum(1 for row in verified if "survey" in (row.get("found_by") or []))
        survey = [
            row
            for row in threats
            if "survey" in (row.get("found_by") or []) and not row.get("verification") and row.get("cwe") in cwes
        ]
        parts = [f"{both} found by both", f"{len(verified) - both} only by Verify", f"{len(survey)} only by the survey"]
        if contradicted := sum(1 for row in survey if row.get("verification_contradicted")):
            parts.append(f"{contradicted} contradicted")
        lines.append(f"{aspect} · " + " · ".join(parts))
    return lines


def aspect_cwes(catalog, aspect: str) -> set[str]:
    """The CWEs of an aspect's catalog verification items."""
    return {cwe for case in catalog["test_cases"] if case["aspect"] == aspect for cwe in case["cwe"]}


def _count(count: int, singular: str, plural: str | None = None) -> str:
    return f"{count} {singular if count == 1 else plural or singular + 's'}"


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
    """Candidates per test case as context data: qualified anchors, each route's method and path, and for a
    candidate inside a handler the routes that reach it with the lines where they and their guards are registered."""
    listed = []
    for case_id, rows in precheck.items():
        candidates = []
        for row in rows:
            candidate = {**row, "anchor": {"repository_id": rid, **row["anchor"]}}
            if "route_id" in row:
                candidate["route"] = _route(facts, row["route_id"])
            if "reached_by" in row:
                candidate["reached_by"] = [_reaching_route(facts, rid, key) for key in row["reached_by"]]
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


def _reaching_route(facts, rid: str, route_id: str) -> dict:
    """A route whose handler reaches a candidate: its method and path, and where it and its guards are registered.

    Locations only, without source: the preload serves the reaching routes' guards only from room the candidates
    leave, so a job whose room the candidates fill still knows which lines decide the candidate.
    """
    route = facts["routes"][route_id]
    lines = sorted({*route.get("guard_lines", []), route["handler_line"]})
    registered = [{"repository_id": rid, "file": route["handler_file"], "line": line} for line in lines]
    return {"route_id": route_id, **_route(facts, route_id), "registered_at": registered}


def _route(facts, route_id: str) -> dict:
    route = facts["routes"][route_id]
    return {"method": route["method"], "path": route["path"], **({"generated": True} if route["generated"] else {})}


def _preload(scope, context, precheck, rid, facts, envelope, architecture, components, limit) -> list[tuple]:
    """Preload as the STRIDE job does: the context's cited lines, guards, candidate windows, then helpers.

    The definitions of the middlewares the candidates' routes run come before
    the candidates: one guard decides many routes, and a guard the job cannot
    read leaves its routes undecidable. The data models that generators serve
    on the candidates' routes follow, since library code handles those routes
    with the fields the model defines. The candidates' anchors and resolved
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
    anchors, lines, guards, models, targets = [], [], [], [], []
    for row in (row for rows in precheck.values() for row in rows):
        anchor = {"repository_id": rid, **row["anchor"]}
        anchors.append(anchor)
        route = facts["routes"].get(row.get("route_id")) or {}
        lines += [{"repository_id": rid, "file": path, "line": first} for path, first, _ in route.get("chain", [])]
        # A sink can lie far into a long handler.
        lines += [{"repository_id": rid, **sink} for sink in row.get("sinks", [])]
        if route.get("data_model"):
            models.append({"repository_id": rid, "file": route["data_model"][0], "line": route["data_model"][1]})
        # The guards of the candidate's route decide it. A location inside a handler is decided by the routes
        # reaching it: their guards and registrations fill leftover room, so they never displace a candidate.
        registered, middleware = [], []
        for key in [row["route_id"]] if "route_id" in row else row.get("reached_by", []):
            reached = facts["routes"].get(key) or {}
            spans = [*wares.get(key, []), *reached.get("guards", [])]
            lines_before = (inventory.get(key) or {}).get("guard_lines") or []
            if key == row.get("route_id"):
                guards += [{"repository_id": rid, "file": path, "line": start} for path, start, _ in spans]
            elif reached:
                middleware += [[rid, path, start, end] for path, start, end in spans]
                lines_before = [*lines_before, reached["handler_line"]]
            registered += [[rid, reached.get("handler_file"), line] for line in lines_before]
        targets.append({"evidence": anchor, "guard_lines": registered, "middleware": middleware})
    served = list(context_preload)
    # Middleware definitions get a quarter of what is left, data models a quarter of the rest, the candidates the rest.
    for rows, share, before, after in (
        (guards, 4, 0, analysis.MAX_MIDDLEWARE_LINES - 1),
        (models, 4, 0, MAX_MODEL_LINES - 1),
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
