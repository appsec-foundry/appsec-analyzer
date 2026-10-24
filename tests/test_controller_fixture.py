"""One offline single-repository controller run over a small web application (`make test-controller`).

The other controller tests assess a two-line `app.py`, so the deterministic
stages between model calls never see real structure. This fixture gives them
some: a browser client calling its own Express API through a verified bearer
guard, a public login route and a route behind an unresolvable guard. The
fake host answers every model role with contract-valid replies; route
inventory, client-to-API flows, the route fill, the architecture gate,
abuse matching, rendering and publication run for real.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from model import case_candidates, case_outcomes
from orchestrator import orchestration_controller as controller
from runtime.analyst_host import HostReply, TransportError
from runtime.assessment_host import MARKER
from validators.validate_intermediate import validate_threat_model_output

from tests.test_multi_repo_assessment import FullHost, _assess

FILES = {
    "server.js": (
        "const express = require('express')\n"
        "const permit = require('permit-guard')\n"
        "const { authenticate } = require('./lib/auth')\n"
        "const reports = require('./lib/reports')\n"
        "\n"
        "const app = express()\n"
        "\n"
        "app.get('/api/orders/:id', authenticate, (req, res) => res.json({ id: req.params.id, owner: req.user.id }))\n"
        "app.post('/rest/login', (req, res) => res.json({ user: req.body.email }))\n"
        "app.get('/rest/reports', permit.check(), reports.list())\n"
        "\n"
        "app.listen(3000)\n"
    ),
    "lib/auth.js": (
        "const jwt = require('jsonwebtoken')\n"
        "module.exports.authenticate = (req, res, next) => {\n"
        "  const token = (req.headers.authorization || '').replace('Bearer ', '')\n"
        "  try {\n"
        "    req.user = jwt.verify(token, process.env.TOKEN_PUBLIC_KEY)\n"
        "  } catch (error) {\n"
        "    return res.status(401).end()\n"
        "  }\n"
        "  next()\n"
        "}\n"
    ),
    "lib/reports.js": "module.exports.list = () => (req, res) => res.json({ query: req.query.q })\n",
    "web/src/api.ts": (
        "export const order = (http, id) => http.get(`/api/orders/${id}`)\n"
        "export const login = (http, credentials) => http.post('/rest/login', credentials)\n"
        "export const reports = (http) => http.get('/rest/reports')\n"
    ),
}


class WebApplicationHost(FullHost):
    """FullHost with a recon answer that splits the fixture into a browser client and its API."""

    def invoke(self, role, system, prompt, schema, timeout_s, should_stop):
        if role == "abuse_case_verifier":
            reply = self.verify_abuse_case(prompt)
        else:
            reply = super().invoke(role, system, prompt, schema, timeout_s, should_stop)
        artifact = reply.payload.get("artifact")
        if role == "recon_scanner" and reply.payload.get("action") == "read":
            # A component may cite only what its task read.
            reads = reply.payload["reads"]
            listed = {row["path"] for row in reads}
            rid = reads[0]["repository_id"]
            reads += [
                dict(repository_id=rid, path=path, start_line=1, end_line=2) for path in FILES if path not in listed
            ]
        if role == "actor_discoverer" and artifact:
            # The shared fake cites every read file; an actor allows four citations.
            for row in artifact.get("proposed_additional") or []:
                row["evidence"] = row["evidence"][:4]
        if role == "recon_scanner" and artifact:
            service = artifact["components"][0]
            service["paths"] = sorted({*service["paths"], "server.js", "lib/auth.js", "lib/reports.js"})
            client = dict(
                id="web",
                name="Browser client",
                description="Single-page client calling the API.",
                tier="client",
                paths=["web/src/api.ts"],
            )
            artifact["components"] = [service, client]
            artifact["interfaces"] = []
        _assert_schema_valid(role, schema, reply.payload)
        return reply

    @staticmethod
    def verify_abuse_case(prompt):
        """Every step inconclusive: a valid verdict that needs no source read."""
        context = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])["context"]
        body = context["candidate_context"]["candidate"]
        verdicts = [
            dict(
                step=row["step"],
                verdict="inconclusive",
                state="decided",
                matched_finding_id=None,
                reason="The fixture host does not judge abuse cases.",
                evidence=None,
                controls_found=[],
            )
            for row in body.get("chain") or body.get("steps") or []
        ]
        artifact = {"abuse_case_id": body["abuse_case_id"], "step_verdicts": verdicts}
        return HostReply(dict(action="complete", reads=[], artifact=artifact), 0.01)


class PilotHost(WebApplicationHost):
    """WebApplicationHost that also answers the REQ-040 test case investigator.

    The first candidate of each job, the first of TC-AUTHZ-01 when one job
    answers all, is a weakness with the finding ``authz-1``; every other
    candidate is neither. With ``fail`` every investigator call fails with
    its cost settled, with ``fail_job`` only the calls of that job of several;
    with ``comment_line`` the first candidate claims a control cited at that
    line. ``interrupt`` rejects the security architecture render, so a later
    run can resume.
    """

    def __init__(self, fail=False, comment_line=None, fail_job=None):
        super().__init__()
        self.fail, self.comment_line, self.interrupt, self.fail_job = fail, comment_line, False, fail_job
        self.investigations = []
        # Per investigation call: its candidate_jobs context and its candidate IDs per test case.
        self.jobs = []
        # Per investigation call: the candidates its context lists.
        self.listed = []
        # The (path, first line, last line) of each investigation's first packet.
        self.served = []
        # The starting files each investigation's context lists.
        self.starting = []
        self.stride_prompts = []
        # Per investigation call: its instructions and its prompt's cache blocks.
        self.systems = []
        self.blocks = []

    def invoke(self, role, system, prompt, schema, timeout_s, should_stop):
        if role == "stride_analyzer":
            self.stride_prompts.append((system, prompt))
        if role == "secarch_renderer" and self.interrupt:
            return HostReply(dict(action="complete", reads=[], artifact={"unexpected": True}), 0.01)
        if role != "test_case_investigator":
            return super().invoke(role, system, prompt, schema, timeout_s, should_stop)
        self.systems.append(system)
        self.blocks.append(prompt.blocks)
        if self.fail:
            raise TransportError("host call failed: no_result", reason="no_result", usd=0.0)
        packet = json.loads(prompt.split(f"<<<{MARKER}\n")[1].split(f"\n{MARKER}>>>")[0])
        context = packet["context"]
        if "test_case_candidates" in context:
            share = {
                row["test_case_id"]: [c["candidate_id"] for c in row["candidates"]]
                for row in context["test_case_candidates"]
            }
            self.jobs.append((context.get("candidate_jobs"), share))
            self.listed.append(context["test_case_candidates"])
            if self.fail_job is not None and (context.get("candidate_jobs") or {}).get("job") == self.fail_job:
                raise TransportError("host call failed: no_result", reason="no_result", usd=0.0)
        if "anchor_corrections" in context:
            # Keep the rejected citation, as a model insisting on it would.
            payload = {
                "anchors": [dict(anchor_id=row["anchor_id"], line=row["line"]) for row in context["anchor_corrections"]]
            }
        else:
            self.investigations.append((context["component"]["id"], context["aspect"]))
            self.served.append({(row["path"], row["start_line"], row["end_line"]) for row in packet["source_slices"]})
            self.starting.append(context.get("starting_files"))
            payload = dict(action="complete", reads=[], artifact=self.investigate(context, packet["source_slices"]))
        _assert_schema_valid(role, schema, payload)
        return HostReply(payload, 0.01)

    def investigate(self, context, slices):
        hashes = {(row["repository_id"], row["path"]): row["sha256"] for row in slices}
        cases, findings, first = [], [], True
        for case in context["test_case_candidates"]:
            answers = []
            for candidate in case["candidates"]:
                answer = dict(
                    candidate_id=candidate["candidate_id"],
                    origin="pre-check",
                    status="neither",
                    evidence=[],
                    finding_ids=[],
                )
                if first:
                    first = False
                    anchor = candidate["anchor"]
                    cited = dict(
                        repository_id=anchor["repository_id"],
                        file=anchor["file"],
                        line=self.comment_line or anchor["line"],
                        sha256=hashes[anchor["repository_id"], anchor["file"]],
                    )
                    if self.comment_line:
                        answer.update(status="control", control_kind="code", evidence=[cited])
                    else:
                        answer.update(status="weakness", evidence=[cited], finding_ids=["authz-1"])
                        findings.append(_owner_finding(cited, candidate["candidate_id"], case["test_case_id"]))
                answers.append(answer)
            cases.append(
                dict(
                    test_case_id=case["test_case_id"],
                    proposed_outcome="finding" if any(row["status"] == "weakness" for row in answers) else "no_finding",
                    reason="The fixture host judges only the first owner check.",
                    candidates=answers,
                )
            )
        return dict(
            schema_version=1,
            source_scope_sha256=context["source_scope_sha256"],
            component_inventory_fingerprint=context["component_inventory_fingerprint"],
            component_id=context["component"]["id"],
            aspect=context["aspect"],
            test_cases=cases,
            findings=findings,
            discovery_escapes=[],
        )


def _owner_finding(cited, candidate_id, case_id="TC-AUTHZ-01"):
    return dict(
        local_id="authz-1",
        title="Order access lacks an owner check",
        stride="Elevation of Privilege",
        scenario="An authenticated user requests another customer's order by its identifier.",
        likelihood="Medium",
        impact="High",
        risk="High",
        evidence=cited,
        evidence_tier="insecure-practice",
        threat_category_id="TH-06",
        cwe="CWE-639",
        remediation=dict(
            effort="Low",
            steps=["Load the order through the caller's account.", "Return 404 when the owner differs."],
            verification="Request another user's order and assert a 404 response.",
        ),
        test_case_ids=[case_id],
        candidate_ids=[candidate_id],
    )


def _assert_schema_valid(role, schema, payload):
    """A fake reply the real CLI could not produce fails here, naming the rule it broke."""
    import jsonschema

    def leaves(errors):
        for error in errors:
            if error.context:
                yield from leaves(error.context)
            else:
                yield f"{'/'.join(map(str, error.absolute_path))}: {error.validator} {str(error.validator_value)[:80]}"

    problems = sorted(set(leaves(jsonschema.Draft202012Validator(schema).iter_errors(payload))))
    assert not problems, f"fake {role} reply breaks its schema: {problems[:5]}"


def _seed(roots):
    for path, text in FILES.items():
        target = roots[0] / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)


def test_web_application_run_publishes_a_valid_model(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    outcome, _, out = _assess(tmp_path, monkeypatch, ("shop",), ("--no-pdf",), seed=_seed, host=WebApplicationHost())
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    assert validate_threat_model_output(model)[0]

    # Client-to-API flows from the routes the client requests, one per proven authentication.
    client = next(c["id"] for c in model["components"] if c.get("tier") == "client")
    api = [f for f in model["data_flows"] if f.get("from") == client and f.get("provenance") == "route-extraction"]
    schemes = sorted((f.get("authentication") or {}).get("scheme", "unknown") for f in api)
    assert schemes == ["bearer", "none", "unknown"]
    # An access group keeps only members whose authentication the route fill proved.
    grouped = [f for f in api if f.get("access_group")]
    assert sorted(f["authentication"]["scheme"] for f in grouped) == ["bearer", "none"]

    head = subprocess.run(["git", "-C", str(tmp_path / "shop"), "rev-parse", "HEAD"], capture_output=True, text=True)
    assert model["meta"]["git"]["commit_sha"] == head.stdout.strip(), "the published model names its source revision"
    assert model.get("abuse_case_analysis", {}).get("status") != "not_run"


def test_test_cases_are_recorded_and_reported_only_when_the_profile_enables_them(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    outcome, host, out = _assess(
        tmp_path, monkeypatch, ("shop",), ("--no-pdf", "--test-cases"), seed=_seed, host=WebApplicationHost()
    )
    assert outcome["status"] == "complete"
    # The boolean form selects no aspect, so no test case is investigated by a model.
    assert "test_case_investigator" not in host.roles
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    assert validate_threat_model_output(model)[0]
    block = model["test_case_results"]
    assert {row["test_case_id"] for row in block["results"]} >= {"TC-CI-01", "TC-INFRA-01", "TC-SUPPLY-01"}
    assert all(row["outcome"] != "control" or row["candidates"]["evidenced"] for row in block["results"])
    report = (out / "security-assessment.md").read_text()
    assert "## Appendix: Verification Items" in report
    linked = [t for t in model["threats"] if t.get("test_case_ids")]
    assert all(t["rule_ids"] for t in linked)


def test_a_profile_disabled_test_case_reports_disabled_and_keeps_its_findings(tmp_path, monkeypatch):
    import functools

    from appsec_analyzer import profiles

    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    profile = profiles.resolve_scan("claude")
    reason = "managed by the platform team"
    profile["settings"]["test_cases"] = {"aspects": ["IAM"], "disable": [{"id": "TC-CI-01", "reason": reason}]}
    from orchestrator import orchestration_controller as controller

    monkeypatch.setattr(
        controller, "assess_repositories", functools.partial(controller.assess_repositories, run_profile=profile)
    )
    outcome, _, out = _assess(tmp_path, monkeypatch, ("shop",), ("--no-pdf",), seed=_seed, host=WebApplicationHost())
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    rows = {row["test_case_id"]: row for row in model["test_case_results"]["results"]}
    assert rows["TC-CI-01"]["outcome"] == "disabled" and rows["TC-CI-01"]["reason"] == reason
    assert rows["TC-INFRA-01"]["outcome"] != "disabled"
    # A disabled test case keeps its scanner findings visible and linked.
    linked = [t["id"] for t in model["threats"] if "TC-CI-01" in t.get("test_case_ids", [])]
    assert rows["TC-CI-01"]["finding_ids"] == linked


def test_test_cases_stay_out_of_the_model_and_report_by_default(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    outcome, host, out = _assess(tmp_path, monkeypatch, ("shop",), ("--no-pdf",), seed=_seed, host=WebApplicationHost())
    assert outcome["status"] == "complete"
    assert "test_case_investigator" not in host.roles
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    assert "test_case_results" not in model and "test_case_findings" not in model
    assert not any("test_case_ids" in threat for threat in model["threats"])
    assert "Appendix: Verification Items" not in (out / "security-assessment.md").read_text()


_PILOT = ("--no-pdf", "--test-case-aspects", "AuthZ")


def _assess_again(tmp_path, host, output, extra, progress=lambda text: None):
    """Assess the `shop` checkout an earlier `_assess` seeded, with the same options as `_assess`."""
    argv = ["--repo", str(tmp_path / "shop"), "--output", str(output), "--hard-budget", "5"]
    argv += ["--trust-mode", "trusted", "--model", "haiku", *extra]
    return controller.assess_repositories(argv, host_factory=host.factory, progress=progress)


def _component_rows(model, case_id=None):
    rows = [row for row in model["test_case_results"]["results"] if row["scope"] == "component"]
    return [row for row in rows if case_id in (None, row["test_case_id"])]


def test_the_authz_pilot_investigates_each_applicable_component_once_and_lists_its_findings_apart(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    host = PilotHost()
    outcome, _, plain = _assess(tmp_path, monkeypatch, ("shop",), ("--no-pdf",), seed=_seed, host=host)
    assert outcome["status"] == "complete" and not host.investigations
    stride = sorted(host.stride_prompts)
    host.stride_prompts.clear()

    outcome = _assess_again(tmp_path, host, tmp_path / "pilot", _PILOT)
    assert outcome["status"] == "complete"
    # The pilot runs after STRIDE on its own jobs: the STRIDE requests do not change.
    assert sorted(host.stride_prompts) == stride
    model = yaml.safe_load((tmp_path / "pilot" / "security-assessment.yaml").read_text())
    assert validate_threat_model_output(model)[0]
    # Component IDs follow the checkout path, so their order varies; the service owns server.js.
    service = next(row for row in model["components"] if "server.js" in row["paths"])
    # The browser client registers no route, so no AuthZ test case applies to it.
    assert host.investigations == [(service["id"], "AuthZ")]
    # The definition of the guard the order route runs arrives with the first packet, as for STRIDE.
    assert any(path == "lib/auth.js" and start <= 2 <= end for path, start, end in host.served[0])

    authz = {"TC-AUTHZ-01", "TC-AUTHZ-02", "TC-AUTHZ-03", "TC-AUTHZ-04", "TC-AUTHZ-05", "TC-AUTHZ-06"}
    assert {(row["component_id"], row["test_case_id"]) for row in _component_rows(model)} == {
        (component["id"], case_id) for component in model["components"] for case_id in authz
    }
    (owner,) = [row for row in _component_rows(model, "TC-AUTHZ-01") if row["component_id"] == service["id"]]
    assert owner["outcome"] == "finding" and owner["finding_ids"] == ["TCF-001"]
    assert owner["evidence_basis"] == "model" and owner["post_checks"]
    assert all(row["outcome"] != "control" for row in _component_rows(model))

    # Pilot findings stay a separate list: the threats are those of the run without the pilot.
    (finding,) = model["test_case_findings"]
    assert finding["id"] == "TCF-001" and finding["component_id"] == service["id"]
    assert finding["test_case_ids"] == ["TC-AUTHZ-01"] and finding["evidence"]["file"] == "server.js"
    without = yaml.safe_load((plain / "security-assessment.yaml").read_text())
    assert sorted(t["title"] for t in model["threats"]) == sorted(t["title"] for t in without["threats"])
    assert not any(t["id"].startswith("TCF-") or t["title"] == finding["title"] for t in model["threats"])

    (sidecar,) = (tmp_path / "pilot").rglob(".test-case-pilot.json")
    document = json.loads(sidecar.read_text())
    assert document["aspects"] == ["AuthZ"] and document["results"] == _component_rows(model)
    artifact = sidecar.parent / ".dispatch-context" / service["id"] / "test-case-candidates.json"
    candidates = json.loads(artifact.read_text())["test_cases"]
    assert {row["test_case_id"] for row in candidates} <= authz and all(row["aspect"] == "AuthZ" for row in candidates)

    report = (tmp_path / "pilot" / "security-assessment.md").read_text()
    assert f"| [TC-AUTHZ-01](#tc-authz-01) · {service['name']} | AuthZ | Finding |" in report
    assert "## Verification Findings" in report and "do not count in the totals of the findings register" in report
    assert "| TCF-001 | [TC-AUTHZ-01](#tc-authz-01) |" in report


def test_a_failed_investigation_records_undecidable_with_a_warning_and_the_run_completes(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    host = PilotHost(fail=True)
    outcome, _, out = _assess(tmp_path, monkeypatch, ("shop",), _PILOT, seed=_seed, host=host)
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    assert validate_threat_model_output(model)[0]
    investigated = [row for row in _component_rows(model) if row["outcome"] not in ("not_applicable", "disabled")]
    assert investigated and all(row["outcome"] == "undecidable" for row in investigated)
    assert {row["reason"] for row in investigated} == {"the model investigation returned no acceptable result"}
    assert "test_case_findings" not in model
    assert any("verification job" in text for text in outcome["warnings"])


def test_a_control_cited_from_a_comment_never_becomes_a_control(tmp_path, monkeypatch):
    def seed(roots):
        _seed(roots)
        with (roots[0] / "server.js").open("a") as handle:
            handle.write("// Every order route compares the order's owner with the caller.\n")

    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    host = PilotHost(comment_line=13)
    outcome, _, out = _assess(tmp_path, monkeypatch, ("shop",), _PILOT, seed=seed, host=host)
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    assert all(row["outcome"] != "control" for row in _component_rows(model))
    owner = [row for row in _component_rows(model, "TC-AUTHZ-01") if row["outcome"] != "not_applicable"]
    assert [row["outcome"] for row in owner] == ["undecidable"]


@pytest.mark.parametrize("batched", [False, True])
def test_resume_replays_accepted_investigations_without_new_model_calls(tmp_path, monkeypatch, batched):
    from runtime.assessment_host import ExchangeError

    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    if batched:
        monkeypatch.setattr(case_candidates, "MAX_CANDIDATES", 1)
    host = PilotHost()
    host.interrupt = True
    with pytest.raises(ExchangeError):
        _assess(tmp_path, monkeypatch, ("shop",), _PILOT, seed=_seed, host=host)
    assert "test_case_investigator" in host.roles
    assert (len(host.jobs) > 1) is batched
    host.roles.clear()
    host.interrupt = False
    outcome = _assess_again(tmp_path, host, tmp_path / "out", (*_PILOT, "--resume"))
    assert outcome["status"] == "complete"
    assert "test_case_investigator" not in host.roles and "stride_analyzer" not in host.roles
    model = yaml.safe_load((tmp_path / "out" / "security-assessment.yaml").read_text())
    ids = [row["id"] for row in model["test_case_findings"]]
    assert ids == [f"TCF-{number:03d}" for number in range(1, len(ids) + 1)] and (len(ids) > 1) is batched


def test_generated_routes_reach_only_the_pilot_marked_and_with_their_generator_call(tmp_path, monkeypatch):
    def seed(roots):
        _seed(roots)
        with (roots[0] / "server.js").open("a") as handle:
            handle.write(
                "const finale = require('finale-rest')\n"
                "finale.initialize({ app })\n"
                "finale.resource({ endpoints: ['/api/Products', '/api/Products/:id'] })\n"
            )

    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    host = PilotHost()
    outcome, _, out = _assess(tmp_path, monkeypatch, ("shop",), _PILOT, seed=seed, host=host)
    assert outcome["status"] == "complete"
    assert validate_threat_model_output(yaml.safe_load((out / "security-assessment.yaml").read_text()))[0]
    (listed,) = host.listed
    routes = {
        case["test_case_id"]: {(row["route"]["method"], row["route"]["path"]): row for row in case["candidates"]}
        for case in listed
    }
    update = routes["TC-AUTHZ-02"]["PUT", "/api/Products/:id"]
    assert update["route"]["generated"] is True and update["anchor"]["line"] == 15
    assert routes["TC-AUTHZ-03"]["POST", "/api/Products"]["route"]["generated"] is True
    assert "generated" not in routes["TC-AUTHZ-01"]["GET", "/api/orders/:id"]["route"]
    # The generator call is served with the first packet, as a candidate's anchor.
    assert any(path == "server.js" and start <= 15 <= end for path, start, end in host.served[0])
    # STRIDE, the report and the other commands keep the inventory without generated routes.
    (inventory,) = out.rglob(".route-inventory.json")
    assert not any(row["path"].startswith("/api/Products") for row in json.loads(inventory.read_text())["routes"])


def test_each_aspect_gets_its_own_jobs_and_an_aspect_without_candidates_gets_none(tmp_path, monkeypatch):
    def seed(roots):
        _seed(roots)
        # The reports handler now builds SQL from the query string.
        (roots[0] / "lib/reports.js").write_text(
            "module.exports.list = () => (req, res) =>\n"
            "  db.query('SELECT * FROM reports WHERE q = ' + req.query.q).then(rows => res.json(rows))\n"
        )

    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    host = PilotHost()
    aspects = ("--no-pdf", "--test-case-aspects", "AuthZ,InputVal,DataProt,AI")
    outcome, _, out = _assess(tmp_path, monkeypatch, ("shop",), aspects, seed=seed, host=host)
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    assert validate_threat_model_output(model)[0]
    service = _service(model)
    # One job per component and aspect; no language model is called, so AI applies nowhere.
    assert sorted(host.investigations) == [(service, "AuthZ"), (service, "DataProt"), (service, "InputVal")]
    listed = {
        case["test_case_id"]: case["candidates"]
        for share in host.listed
        for case in share
        if case["test_case_id"].startswith(("TC-INPUT", "TC-DATA"))
    }
    (reports,) = listed["TC-INPUT-01"]
    assert reports["route"] == {"method": "GET", "path": "/rest/reports"}
    assert reports["sinks"] == [{"file": "lib/reports.js", "line": 2}]
    # The goal test cases ride along in the first job without candidates of their own.
    assert listed["TC-INPUT-07"] == [] and listed["TC-DATA-05"] == []
    # The browser client has data protection test cases but no candidate, so no job ran for them.
    client = next(row["id"] for row in model["components"] if row["id"] != service)
    skipped = [
        row for row in _component_rows(model) if row["component_id"] == client and row["outcome"] == "undecidable"
    ]
    assert skipped and {row["reason"] for row in skipped} == {
        "no test case of the aspect has a starting candidate in the component, so no model job ran"
    }


def test_a_language_model_call_gets_an_ai_job_whose_reply_passes_the_contract(tmp_path, monkeypatch):
    def seed(roots):
        _seed(roots)
        # The reports handler now asks a language model with the request's text.
        (roots[0] / "lib/reports.js").write_text(
            "const OpenAI = require('openai')\n"
            "const client = new OpenAI()\n"
            "module.exports.list = () => async (req, res) =>\n"
            "  res.json(await client.chat.completions.create({ model: 'm', messages: [{ role: 'user', "
            "content: req.query.q }] }))\n"
        )

    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    host = PilotHost()
    aspects = ("--no-pdf", "--test-case-aspects", "AI")
    outcome, _, out = _assess(tmp_path, monkeypatch, ("shop",), aspects, seed=seed, host=host)
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    service = _service(model)
    # The fake host's reply passes the projected schema the real CLI enforces, and the job is accepted.
    assert host.investigations == [(service, "AI")]
    rows = [row for row in _component_rows(model) if row["component_id"] == service]
    assert rows and {row["aspect"] for row in rows} == {"AI"}
    assert case_outcomes.REPLACEMENT_REASONS["failure"] not in {row["reason"] for row in rows}
    assert any(row["outcome"] == "finding" for row in rows)
    # The context names the starting files: the first packet's files and the candidates' anchors.
    (starting,) = host.starting
    anchors = {row["anchor"]["file"] for case in host.listed[0] for row in case["candidates"]}
    assert {row["path"] for row in starting} == {path for path, _, _ in host.served[0]} | anchors


def _service(model):
    return next(row["id"] for row in model["components"] if "server.js" in row["paths"])


def _calls(host):
    """The candidate IDs per test case of each investigation job, by job number, once per job."""
    return {(jobs or {}).get("job", 1): (jobs, share) for jobs, share in host.jobs}


def test_shared_candidates_are_answered_once_and_combined_into_one_row_per_test_case(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    host = PilotHost()
    outcome, _, plain = _assess(tmp_path, monkeypatch, ("shop",), ("--no-pdf",), seed=_seed, host=host)
    assert outcome["status"] == "complete"
    stride = sorted(host.stride_prompts)
    host.stride_prompts.clear()

    # One candidate per job forces every location into its own job.
    monkeypatch.setattr(case_candidates, "MAX_CANDIDATES", 1)
    said = []
    outcome = _assess_again(tmp_path, host, tmp_path / "pilot", _PILOT, progress=said.append)
    assert outcome["status"] == "complete"
    assert sorted(host.stride_prompts) == stride
    model = yaml.safe_load((tmp_path / "pilot" / "security-assessment.yaml").read_text())
    assert validate_threat_model_output(model)[0]
    service = _service(model)
    calls = _calls(host)
    count = len(calls)
    assert count > 1 and host.investigations == [(service, "AuthZ")] * count
    # The progress names the components to verify and each job's part of its component.
    name = next(row["name"] for row in model["components"] if row["id"] == service)
    # REQ-040: the plan comes before the survey and ends with the job count the live progress weighs.
    planned = said.index(f"Verify planned · 1 component for AuthZ after the survey · {count} jobs")
    assert planned < min(said.index(text) for text in said if text.startswith("Surveying component"))
    # Before the first job the run says whether the remaining budget covers them all.
    (start,) = [text for text in said if text.startswith("Verify start · ")]
    assert start.startswith("Verify start · 1 component for AuthZ · about USD ") and " of the budget left" in start
    assert start.endswith(f" · {count} jobs")
    assert said.index(start) < min(said.index(text) for text in said if text.startswith("Verifying component "))
    jobs = [f"component 1/1, part {number}/{count}, AuthZ: {name}" for number in range(1, count + 1)]
    assert {text for text in said if text.startswith("Verifying component ")} == {f"Verifying {job}" for job in jobs}
    # Each job reports its end after its start, so the console counts finished jobs.
    assert all(said.index(f"Verifying {job}") < said.index(f"Finished verifying {job}") for job in jobs)
    # The jobs share their instructions and their prompts' start up to the component context and aspect,
    # and a later job starts once the first has written that start into the prompt cache.
    assert len(set(host.systems)) == 1 and len({blocks[:2] for blocks in host.blocks}) == 1
    assert all(len(blocks) == 4 for blocks in host.blocks) and host.blocks[0][1].endswith('"aspect": "AuthZ"')
    assert all(said.index(f"Verifying {job}") > said.index(f"Finished verifying {jobs[0]}") for job in jobs[1:])
    summary = (
        f"Verify done · AuthZ · {len(_component_rows(model))} results, {len(model['test_case_findings'])} findings"
    )
    assert said.index(summary) > max(said.index(f"Finished verifying {job}") for job in jobs)

    # Each pre-check candidate is answered in exactly one job; together the jobs answer all of them.
    answered = [cid for _, share in calls.values() for ids in share.values() for cid in ids]
    (artifact,) = (tmp_path / "pilot").rglob(f".dispatch-context/{service}/test-case-candidates.json")
    listed = [
        row["candidate_id"] for case in json.loads(artifact.read_text())["test_cases"] for row in case["candidates"]
    ]
    assert sorted(answered) == sorted(listed) and len(set(answered)) == len(answered)
    # Only the first job answers every test case, adds model candidates, and learns where the others answer.
    jobs = [calls[number][0] for number in range(1, count + 1)]
    assert [(row["job"], row["of"], row["adds_candidates"]) for row in jobs] == [
        (number, count, number == 1) for number in range(1, count + 1)
    ]
    assert "answered_elsewhere" in jobs[0] and not any("answered_elsewhere" in row for row in jobs[1:])
    assert set(calls[1][1]) >= {case for _, share in calls.values() for case in share}

    # One row per test case and component, counting the candidates of every job and none as unexamined.
    rows = {row["test_case_id"]: row for row in _component_rows(model) if row["component_id"] == service}
    for case_id, row in rows.items():
        total = sum(len(share.get(case_id, [])) for _, share in calls.values())
        assert row["candidates"]["unexamined"] == 0 and row["candidates"]["applicable"] == total
    assert len(_component_rows(model)) == len(
        {(row["component_id"], row["test_case_id"]) for row in _component_rows(model)}
    )

    # Every job reports its finding as authz-1; the pilot findings keep distinct IDs and links.
    ids = [row["id"] for row in model["test_case_findings"]]
    assert len(ids) > 1 and ids == [f"TCF-{number:03d}" for number in range(1, len(ids) + 1)]
    assert sorted(value for row in _component_rows(model) for value in row["finding_ids"]) == sorted(ids)


def test_a_failed_job_makes_only_its_candidates_undecidable(tmp_path, monkeypatch):
    monkeypatch.setenv("APPSEC_SINGLE_REPO_CONTROLLER", "1")
    monkeypatch.setattr(case_candidates, "MAX_CANDIDATES", 1)
    host = PilotHost(fail_job=2)
    outcome, _, out = _assess(tmp_path, monkeypatch, ("shop",), _PILOT, seed=_seed, host=host)
    assert outcome["status"] == "complete"
    assert any("verification job" in text for text in outcome["warnings"])
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    assert validate_threat_model_output(model)[0]
    rows = {row["test_case_id"]: row for row in _component_rows(model) if row["component_id"] == _service(model)}
    failed = {case_id: ids for case_id, ids in _calls(host)[2][1].items() if ids}
    assert failed
    reason = case_outcomes.REPLACEMENT_REASONS["failure"]
    for case_id, ids in failed.items():
        row = rows[case_id]
        # The failed job's candidates count as undecidable, not unexamined, and never as a control.
        assert row["candidates"]["undecidable"] >= len(ids) and row["candidates"]["unexamined"] == 0
        assert row["outcome"] in ("finding", "partial", "undecidable")
        # The test case keeps the answers of its other jobs instead of becoming one replaced result.
        assert row["reason"] != reason
        if row["outcome"] == "undecidable":
            assert row["reason"].endswith(f"candidate locations undecidable: {reason}")
    # The first job's finding survives the failure of the second.
    assert model["test_case_findings"][0]["test_case_ids"] == ["TC-AUTHZ-01"]
