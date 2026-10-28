"""Deterministic scanner findings keep their repository, hash and local owner."""

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from model import assessment_scanner_findings
from model.assessment_scanner_findings import own_scanner_anchors, scan

from tests.test_multi_repo_boundaries import fixture

JWT = 'const jwt = require("jsonwebtoken");\nfunction read(token) {\n  return jwt.decode(token);\n}\n'
SHELL = (
    "import subprocess\nfrom flask import request\n\ndef run():\n"
    '    name = request.args["name"]\n    return subprocess.call("ls " + name, shell=True)\n'
)


def finalized(tmp_path, **kwargs):
    """The shared fixture after component finalization's scanner-anchor ownership step."""
    scope, components, evidence = fixture(tmp_path, **kwargs)
    own_scanner_anchors(scope, components["components"])
    return scope, components, evidence


def by_label(scope):
    return {repo.root.name: repo for repo in scope.repositories}


@pytest.mark.parametrize(
    ("names", "paths"),
    [(("edge", "service"), ("src/token.js", "lib/tool.py")), (("north", "south"), ("web/auth.js", "jobs/run.py"))],
)
def test_findings_are_qualified_and_owned_inside_their_repository(tmp_path, names, paths):
    files = {names[0]: {paths[0]: JWT}, names[1]: {paths[1]: SHELL}}
    scope, components, _ = finalized(tmp_path, names=names, files=files)
    repos = by_label(scope)
    owner = {row["repository_ids"][0]: row["id"] for row in components["components"]}
    result = scan(scope, components)
    assert set(result) == set(owner.values())
    for name, path in zip(names, paths, strict=True):
        repo = repos[name]
        [threat] = result[owner[repo.repository_id]]
        assert threat["source"] == "source-scan"
        assert threat["component_id"] == owner[repo.repository_id]
        assert threat["local_id"] == "deterministic-scan-001"
        assert threat["evidence"] == {
            "repository_id": repo.repository_id,
            "file": path,
            "line": threat["evidence"]["line"],
            "sha256": hashlib.sha256(repo.files[path]).hexdigest(),
        }
        assert threat["evidence"]["line"] >= 1


@pytest.mark.parametrize(
    ("names", "paths"),
    [(("edge", "service"), ("src/token.js", "lib/tool.py")), (("north", "south"), ("web/auth.js", "jobs/run.py"))],
)
def test_the_tally_names_every_scanner_and_matches_the_findings(tmp_path, names, paths):
    from model.assessment_scanner_findings import SCANNER_LABELS

    files = {names[0]: {paths[0]: JWT}, names[1]: {paths[1]: SHELL}}
    scope, components, _ = finalized(tmp_path, names=names, files=files)
    tally = {}
    result = scan(scope, components, tally=tally)
    assert list(tally) == list(SCANNER_LABELS)
    assert sum(tally.values()) == sum(len(rows) for rows in result.values()) > 0


def test_the_most_specific_component_of_the_same_repository_owns_a_finding(tmp_path):
    scope, components, _ = fixture(tmp_path, files={"edge": {"src/token.js": JWT}})
    repo = by_label(scope)["edge"]
    sha = hashlib.sha256(repo.files["src/token.js"]).hexdigest()
    components["components"].append(
        dict(
            id="component-token",
            name="Token reader",
            description="Token handling module.",
            tier="application",
            repository_ids=[repo.repository_id],
            paths=[dict(repository_id=repo.repository_id, path="src/token.js", sha256=sha)],
        )
    )
    result = scan(scope, components)
    assert [t["evidence"]["file"] for t in result["component-token"]] == ["src/token.js"]
    assert sum(map(len, result.values())) == 1


def test_equal_relative_paths_in_two_repositories_stay_two_findings(tmp_path):
    scope, components, _ = finalized(
        tmp_path, files={"edge": {"lib/tool.py": SHELL}, "service": {"lib/tool.py": SHELL}}
    )
    threats = [t for rows in scan(scope, components).values() for t in rows]
    assert len(threats) == 2
    assert {t["evidence"]["repository_id"] for t in threats} == {r.repository_id for r in scope.repositories}


def test_repositories_without_scanner_findings_yield_empty_owners(tmp_path):
    scope, components, _ = finalized(tmp_path)
    assert scan(scope, components) == {row["id"]: [] for row in components["components"]}


def test_a_failed_scanner_stops_the_assessment(tmp_path, monkeypatch):
    scope, components, _ = finalized(tmp_path)
    monkeypatch.setattr(assessment_scanner_findings.mass_assignment_scanner, "main", lambda argv: 2)
    with pytest.raises(ValueError, match="scanner failed") as caught:
        scan(scope, components)
    assert caught.value.repository_id in {repo.repository_id for repo in scope.repositories}


@pytest.mark.parametrize("name", ["source_auth_scanner", "authz_confirm", "mass_assignment_scanner"])
def test_failed_scanner_names_the_stage_and_classifies_diagnostics_without_echoing_them(tmp_path, monkeypatch, name):
    import sys

    def fail(argv):
        print("parse error in PRIVATE_SOURCE; password='synthetic-private-value'\nFORGED", file=sys.stderr)
        return 2

    monkeypatch.setattr(getattr(assessment_scanner_findings, name), "main", fail)
    # Other scanners need not create sidecars for this failure-path check.
    for other in {"source_auth_scanner", "authz_confirm", "mass_assignment_scanner"} - {name}:
        monkeypatch.setattr(getattr(assessment_scanner_findings, other), "main", lambda argv: 0)
    with pytest.raises(ValueError) as caught:
        assessment_scanner_findings._run_scanners(tmp_path, tmp_path)
    message = str(caught.value)
    assert name.removesuffix("_scanner").replace("_", "-") in message
    assert "input_parse_error" in message and "exit 2" in message
    assert all(value not in message for value in ("PRIVATE_SOURCE", "synthetic-private-value", "FORGED"))


def test_an_error_stub_cannot_stand_in_for_a_scan(tmp_path, monkeypatch):
    scope, components, _ = finalized(tmp_path)

    def stub(argv):
        output = Path(argv[argv.index("--output-dir") + 1])
        (output / ".source-auth-findings.json").write_text(json.dumps({"parse_error": "boom", "findings": []}))
        return 0

    monkeypatch.setattr(assessment_scanner_findings.source_auth_scanner, "main", stub)
    with pytest.raises(ValueError, match="invalid sidecar"):
        scan(scope, components)


DOCKERFILE = 'FROM node:latest\nCOPY . .\nRUN npm install\nCMD ["node", "app.js"]\n'


@pytest.mark.parametrize(
    ("names", "path"), [(("edge", "service"), "Dockerfile"), (("north", "south"), "deploy/Dockerfile")]
)
def test_config_findings_with_a_source_line_are_qualified_and_owned(tmp_path, names, path):
    scope, components, _ = finalized(tmp_path, names=names, files={names[0]: {path: DOCKERFILE}})
    repo = by_label(scope)[names[0]]
    owner = {row["repository_ids"][0]: row["id"] for row in components["components"]}
    threats = [t for t in scan(scope, components)[owner[repo.repository_id]] if t["source"] == "config-scan"]
    assert threats
    for threat in threats:
        assert threat["component_id"] == owner[repo.repository_id]
        assert threat["evidence"]["repository_id"] == repo.repository_id
        assert threat["evidence"]["file"] == path and threat["evidence"]["line"] >= 1
        assert threat["evidence"]["sha256"] == hashlib.sha256(repo.files[path]).hexdigest()
        assert threat["local_id"].startswith("deterministic-scan-")


def test_equal_config_paths_in_two_repositories_stay_distinct(tmp_path):
    files = {"edge": {"Dockerfile": DOCKERFILE}, "service": {"Dockerfile": DOCKERFILE}}
    scope, components, _ = finalized(tmp_path, files=files)
    threats = [t for rows in scan(scope, components).values() for t in rows if t["source"] == "config-scan"]
    by_repository = {}
    for threat in threats:
        by_repository.setdefault(threat["evidence"]["repository_id"], set()).add(threat["config_check_id"])
    assert set(by_repository) == {r.repository_id for r in scope.repositories}
    assert by_repository[scope.repositories[0].repository_id] == by_repository[scope.repositories[1].repository_id]


def test_a_repository_without_iac_yields_no_config_findings(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(assessment_scanner_findings.config_iac_scanner, "main", lambda argv: called.append(argv) or 2)
    scope, components, _ = finalized(tmp_path, files={"edge": {"lib/tool.py": "VALUE = 1\n"}})
    assert scan(scope, components) == {row["id"]: [] for row in components["components"]}
    assert called == []


def test_depth_reaches_the_config_scanner_and_its_failure_stops_the_assessment(tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(assessment_scanner_findings.config_iac_scanner, "main", lambda argv: called.append(argv) or 2)
    scope, components, _ = fixture(tmp_path, files={"edge": {"Dockerfile": DOCKERFILE}})
    with pytest.raises(ValueError, match=r"config-iac scanner failed: execution_error \(exit 2\)"):
        scan(scope, components, depth="quick")
    assert called[0][called[0].index("--assessment-depth") + 1] == "quick"


@pytest.mark.parametrize(
    ("names", "path"), [(("edge", "service"), "Dockerfile"), (("north", "south"), "ops/Dockerfile")]
)
def test_a_scanner_anchor_its_component_does_not_list_stops_before_any_model_call(tmp_path, names, path):
    scope, components, _ = fixture(tmp_path, names=names, files={names[0]: {path: DOCKERFILE}})
    with pytest.raises(ValueError, match="does not own"):
        scan(scope, components)


@pytest.mark.parametrize(
    ("names", "files"),
    [
        (("edge", "service"), {"Dockerfile": DOCKERFILE, "src/token.js": JWT}),
        (("north", "south"), {"ops/Dockerfile": DOCKERFILE, "web/auth.js": JWT}),
    ],
)
def test_unlisted_scanner_anchors_get_a_listing_owner_in_their_repository(tmp_path, names, files):
    scope, components, _ = fixture(tmp_path, names=names, files={names[0]: files})
    repo = by_label(scope)[names[0]]
    assert own_scanner_anchors(scope, components["components"]) >= len(files)
    [owner] = [row for row in components["components"] if repo.repository_id in row["repository_ids"]]
    assert set(files) <= {p["path"] for p in owner["paths"]}
    assert own_scanner_anchors(scope, components["components"]) == 0
    by_id = {row["id"]: row for row in components["components"]}
    for cid, threats in scan(scope, components).items():
        listed = {(p["repository_id"], p["path"]) for p in by_id[cid]["paths"]}
        assert all((t["evidence"]["repository_id"], t["evidence"]["file"]) in listed for t in threats)


def test_a_scanner_anchor_another_component_lists_keeps_that_owner(tmp_path):
    scope, components, _ = fixture(tmp_path, files={"edge": {"deploy/Dockerfile": DOCKERFILE}})
    repo = by_label(scope)["edge"]
    sha = hashlib.sha256(repo.files["deploy/Dockerfile"]).hexdigest()
    components["components"].append(
        dict(
            id="component-image",
            name="Container image",
            description="Container build definition.",
            tier="application",
            repository_ids=[repo.repository_id],
            paths=[dict(repository_id=repo.repository_id, path="deploy/Dockerfile", sha256=sha)],
        )
    )
    assert own_scanner_anchors(scope, components["components"]) == 0
    config = [t for rows in scan(scope, components).values() for t in rows if t["source"] == "config-scan"]
    assert config and {t["component_id"] for t in config} == {"component-image"}


ROOTLESS = "COPY . .\nRUN make build\n"
HARDENED = "FROM base@sha256:" + "a" * 64 + "\nUSER app\nHEALTHCHECK CMD true\nCOPY . .\n"


def absences(threats):
    return {t["config_check_id"]: t for t in threats if t["evidence"].get("kind") == "absence"}


@pytest.mark.parametrize(
    ("names", "path", "check"),
    [(("edge", "service"), "Dockerfile", "IAC-002"), (("north", "south"), ".github/workflows/build.yml", "IAC-041")],
)
def test_an_absence_is_anchored_at_the_file_it_searched_and_owned_by_its_repository(tmp_path, names, path, check):
    workflow = "name: build\non: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make\n"
    text = ROOTLESS if path == "Dockerfile" else workflow
    scope, components, _ = finalized(tmp_path, names=names, files={names[0]: {path: text}})
    repo = by_label(scope)[names[0]]
    owner = {row["repository_ids"][0]: row["id"] for row in components["components"]}
    result = scan(scope, components)
    threat = absences(result[owner[repo.repository_id]])[check]
    assert threat["evidence"] == {
        "kind": "absence",
        "searched_files": [path],
        "searched_file_count": 1,
        "repository_id": repo.repository_id,
        "file": path,
        "line": 1,
        "sha256": hashlib.sha256(repo.files[path]).hexdigest(),
    }
    other = next(r for r in scope.repositories if r is not repo)
    assert absences(result[owner[other.repository_id]]) == {}


def test_a_present_control_yields_no_absence(tmp_path):
    scope, components, _ = finalized(tmp_path, files={"edge": {"Dockerfile": HARDENED}})
    threats = [t for rows in scan(scope, components).values() for t in rows]
    assert {"IAC-002", "IAC-003"}.isdisjoint(absences(threats))


def test_an_absence_is_reviewed_by_reading_its_file_and_merged(tmp_path):
    from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
    from runtime.multi_repo_scope import admit

    from tests.test_multi_repo_controller import Host, checkout, controller

    roots = [tmp_path / name for name in ("caller", "receiver")]
    for root in roots:
        checkout(root)
    (roots[1] / "Dockerfile").write_text(ROOTLESS)
    scope = admit([str(r) for r in roots], str(tmp_path / "out"))
    host = Host(scope)
    jobs = AssessmentJobs(
        scope, scope.output / ".jobs", AssessmentBudget(2, 0.05, 60, 120), host.factory, lambda: False, lambda: None
    )
    architecture = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    controls = controller._assessment_controls(scope, jobs, architecture, progress=lambda text: None)
    _, _, merged = controller._assessment_stride(scope, jobs, architecture, controls, [], progress=lambda text: None)
    receiver = by_label(scope)["receiver"].repository_id
    rootless = [t for t in merged["threats"] if t.get("config_check_id") == "IAC-002"]
    assert len(rootless) == 1
    assert rootless[0]["evidence"]["repository_id"] == receiver and rootless[0]["evidence"]["file"] == "Dockerfile"
    assert rootless[0]["evidence"]["kind"] == "absence"
    assert rootless[0]["evidence_check"] == "verified"
    owners = {c["id"] for c in architecture["components"]["components"] if c["repository_ids"] == [receiver]}
    assert rootless[0]["component_id"] in owners
    reviews = [ctx for role, ctx in host.calls if role == "evidence_verifier"]
    assert any(f["evidence"]["file"] == "Dockerfile" for ctx in reviews for f in ctx["findings"])


CORS = 'const cors = require("cors");\napp.use(cors({ origin: "*", credentials: true }));\n'


def architecture(threats):
    return [t for t in threats if t["source"] in {"architecture-coverage", "threat-hypothesis"}]


@pytest.mark.parametrize(
    ("names", "path"), [(("edge", "service"), "src/server.js"), (("north", "south"), "web/api.js")]
)
def test_a_high_confidence_architecture_anti_pattern_becomes_an_owned_scanner_finding(tmp_path, names, path):
    scope, components, _ = finalized(tmp_path, names=names, files={names[0]: {path: CORS}})
    repo = by_label(scope)[names[0]]
    owner = {row["repository_ids"][0]: row["id"] for row in components["components"]}
    result = scan(scope, components)
    [threat] = architecture(result[owner[repo.repository_id]])
    assert threat["source"] == "architecture-coverage" and threat["rule_id"] == "ARCH-CORS-001"
    assert threat["component_id"] == owner[repo.repository_id]
    assert threat["local_id"].startswith("deterministic-scan-") and "t_id" not in threat
    # Architecture findings stay unscored and below Critical, as the merge validators require.
    assert threat["risk"] != "Critical" and "cvss_v4" not in threat
    assert threat["evidence"] == {
        "repository_id": repo.repository_id,
        "file": path,
        "line": 2,
        "sha256": hashlib.sha256(repo.files[path]).hexdigest(),
    }
    other = next(r for r in scope.repositories if r is not repo)
    assert architecture(result[owner[other.repository_id]]) == []


def test_an_architecture_finding_names_its_rule_and_items_but_adds_no_verification_candidate(tmp_path):
    from model import case_outcomes
    from model.case_candidates import _scanner_hits

    scope, components, _ = finalized(tmp_path, files={"edge": {"src/server.js": CORS, "src/token.js": JWT}})
    threats = [t for rows in scan(scope, components).values() for t in rows]
    [threat] = architecture(threats)
    case_outcomes.annotate_threats([threat], case_outcomes.load_catalog())
    assert threat["rule_ids"] == ["ARCH-CORS-001"] and "TC-FRONT-01" in threat["test_case_ids"]
    # Verification starting points stay the source and config hits.
    assert _scanner_hits([threat]) == []
    assert _scanner_hits([t for t in threats if t["source"] == "source-scan"])


def test_only_anchored_high_confidence_architecture_hits_become_findings():
    evidence = [{"file": "src/a.js", "line": 3, "signal": "matched line"}]
    rule = dict(cwe="CWE-942", stride="Tampering", severity_cap="High", evidence=evidence)
    coverage = {
        "anti_pattern_candidates": [
            dict(rule, rule_id="ARCH-CORS-001", title="Permissive CORS", confidence="high"),
            dict(rule, rule_id="ARCH-TLS-001", title="Cleartext transport", confidence="medium"),
            dict(
                rule,
                rule_id="ARCH-XSS-002",
                title="Stored XSS",
                confidence="high",
                evidence=[{"file": "src/a.js", "line": None}],
            ),
        ],
        "threat_hypotheses": [
            dict(
                hypothesis_id="ARCH-HYP-DBSEP-001",
                rule_id="ARCH-DBSEP-001",
                title="Shared database principal",
                proof_state="confirmed",
                confidence="high",
                positive_signals=evidence,
            ),
            dict(
                hypothesis_id="ARCH-HYP-AUTHZ-001",
                rule_id="ARCH-AUTHZ-001",
                title="No central authorization",
                proof_state="control-derived",
                confidence="low",
                positive_signals=evidence,
            ),
        ],
    }
    threats = assessment_scanner_findings._architecture_threats(coverage)
    assert [(t["source"], t["rule_id"]) for t in threats] == [
        ("architecture-coverage", "ARCH-CORS-001"),
        ("threat-hypothesis", "ARCH-DBSEP-001"),
    ]
    assert threats[1]["hypothesis_id"] == "ARCH-HYP-DBSEP-001" and threats[1]["risk"] == "High"
    assert all(t["evidence"] == {"file": "src/a.js", "line": 3} for t in threats)


def test_hypotheses_are_numbered_across_repositories_in_repository_order():
    def document():
        return {
            "threat_hypotheses": [{"hypothesis_id": "ARCH-HYP-DBSEP-001"}, {"hypothesis_id": "ARCH-HYP-AUTHZ-001"}],
            "control_assessments": [{"hypothesis_ids": ["ARCH-HYP-DBSEP-001"]}, {"rule_id": "ARCH-CORS-001"}],
        }

    counters: dict[str, int] = {}
    first, second = document(), document()
    for row in (first, second):
        assessment_scanner_findings.renumber_hypotheses(row, counters)
    assert [h["hypothesis_id"] for h in first["threat_hypotheses"]] == ["ARCH-HYP-DBSEP-001", "ARCH-HYP-AUTHZ-001"]
    assert [h["hypothesis_id"] for h in second["threat_hypotheses"]] == ["ARCH-HYP-DBSEP-002", "ARCH-HYP-AUTHZ-002"]
    assert second["control_assessments"] == [{"hypothesis_ids": ["ARCH-HYP-DBSEP-002"]}, {"rule_id": "ARCH-CORS-001"}]


def test_architecture_anchors_and_findings_use_the_assessment_depth(tmp_path, monkeypatch):
    depths = []
    original = assessment_scanner_findings.architecture_scan

    def record(root, output, depth):
        depths.append(depth)
        return original(root, output, depth)

    monkeypatch.setattr(assessment_scanner_findings, "architecture_scan", record)
    scope, components, _ = fixture(tmp_path)
    own_scanner_anchors(scope, components["components"], "thorough")
    scan(scope, components, depth="quick")
    count = len(scope.repositories)
    assert depths == ["thorough"] * count + ["quick"] * count


def test_a_failed_architecture_coverage_stops_the_assessment(tmp_path, monkeypatch):
    scope, components, _ = finalized(tmp_path)
    monkeypatch.setattr(assessment_scanner_findings.architecture_coverage_checks, "_main", lambda argv: 2)
    with pytest.raises(ValueError, match="architecture-coverage scanner failed") as caught:
        scan(scope, components)
    assert caught.value.repository_id in {repo.repository_id for repo in scope.repositories}


@pytest.mark.parametrize("verdict", ["verified", "refuted"])
def test_an_architecture_hit_is_reviewed_with_its_component_and_kept_only_when_confirmed(tmp_path, verdict):
    from runtime.assessment_jobs import AssessmentBudget, AssessmentJobs
    from runtime.multi_repo_scope import admit
    from shared._finding_state import is_refuted

    from tests.test_multi_repo_controller import Host, checkout, controller

    class Reviewer(Host):
        def invoke(self, role, prompt):
            reply = super().invoke(role, prompt)
            if role == "evidence_verifier":
                for decision in reply.payload["artifact"]["decisions"]:
                    if decision["evidence"][0]["file"] == "src/server.js":
                        decision["verdict"] = verdict
            return reply

    roots = [tmp_path / name for name in ("caller", "receiver")]
    for root in roots:
        checkout(root)
    (roots[1] / "src").mkdir()
    (roots[1] / "src/server.js").write_text(CORS)
    scope = admit([str(r) for r in roots], str(tmp_path / "out"))
    host = Reviewer(scope)
    jobs = AssessmentJobs(
        scope, scope.output / ".jobs", AssessmentBudget(2, 0.05, 60, 120), host.factory, lambda: False, lambda: None
    )
    architecture_ = controller._assessment_architecture(scope, jobs, progress=lambda text: None)
    controls = controller._assessment_controls(scope, jobs, architecture_, progress=lambda text: None)
    _, _, merged = controller._assessment_stride(scope, jobs, architecture_, controls, [], progress=lambda text: None)
    [threat] = [t for t in merged["threats"] if t.get("rule_id") == "ARCH-CORS-001"]
    receiver = by_label(scope)["receiver"].repository_id
    assert threat["source"] == "architecture-coverage"
    assert threat["evidence"]["repository_id"] == receiver and threat["evidence"]["file"] == "src/server.js"
    assert threat["evidence_check"] == verdict and is_refuted(threat) == (verdict == "refuted")
    reviews = [ctx for role, ctx in host.calls if role == "evidence_verifier"]
    assert sum(f["evidence"]["file"] == "src/server.js" for ctx in reviews for f in ctx["findings"]) == 1


def test_a_full_assessment_publishes_a_confirmed_architecture_finding_without_a_score(tmp_path, monkeypatch):
    import yaml
    from validators.validate_intermediate import validate_threat_model_output

    from tests.test_multi_repo_assessment import _assess

    def seed(roots):
        (roots[0] / "src").mkdir()
        (roots[0] / "src/server.js").write_text(CORS)

    outcome, _, out = _assess(tmp_path, monkeypatch, ("edge", "service"), ("--no-pdf",), seed=seed)
    assert outcome["status"] == "complete"
    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    assert validate_threat_model_output(model)[0]
    [threat] = [t for t in model["threats"] if t.get("rule_id") == "ARCH-CORS-001"]
    assert threat["source"] == "architecture-coverage" and "cvss_v4" not in threat
    assert threat["evidence_check"] == "verified"
