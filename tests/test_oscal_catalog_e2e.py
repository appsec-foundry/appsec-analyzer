"""The example OSCAL catalog through the public commands, offline.

`examples/brennholt-appsec-catalog.oscal.json` is the catalog of a fictional company, written against the
planted weaknesses of `tests/fixtures/e2e/synthetic-repo`. `tests/fixtures/e2e/oracle/brennholt-audit-verdicts.json`
holds the verdict of each control with its evidence.

`tests/e2e/fake_claude.py` answers with those verdicts. These runs cross the boundaries a real run crosses:
CLI, `claude -p` transport, source admission, report and gate. They do not show that a model reaches the
verdicts; that takes a live run with an authorized budget.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pytest
import yaml

from tests.test_controller_e2e import FAKE_CLAUDE, _assert_published, _headless, _system

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "examples" / "brennholt-appsec-catalog.oscal.json"
FIXTURE = ROOT / "tests" / "fixtures" / "e2e" / "synthetic-repo"
VERDICTS = ROOT / "tests" / "fixtures" / "e2e" / "oracle" / "brennholt-audit-verdicts.json"
TITLE = "Brennholt Logistik Application Security Standard"
# Planted in the fixture lines that the verdict of sec-1 cites; they may reach the model only masked.
SECRETS = ("e2e-fixture-jwt-secret-7f4c91", "e2e-fixture-db-password-91ac")


def _git(repo: Path, *args: str) -> None:
    identity = ("-c", "user.name=Test", "-c", "user.email=test@example.invalid")
    subprocess.run(["git", "-C", str(repo), *identity, *args], check=True, capture_output=True)


def _audit(tmp_path: Path, *extra: str, catalog: Path = CATALOG):
    repo, output, state = tmp_path / "repo", tmp_path / "audit", tmp_path / "fake-claude"
    shutil.copytree(FIXTURE, repo)
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    _git(repo, "commit", "-qm", "fixture")
    output.mkdir(mode=0o700)
    # The audit starts `claude` from PATH whatever APPSEC_CLAUDE_EXECUTABLE says; never let that be the real CLI.
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    stub = stub_dir / "claude"
    stub.symlink_to(FAKE_CLAUDE)
    # The stub runs under the interpreter that runs the tests.
    path = os.pathsep.join((str(stub_dir), str(Path(sys.executable).parent), os.environ.get("PATH", "")))
    assert shutil.which("claude", path=path) == str(stub)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "appsec_analyzer",
            "audit-requirements",
            "--repo",
            str(repo),
            "--output",
            str(output),
            "--host",
            "claude-cli",
            "--requirements",
            str(catalog),
            "--model",
            "haiku",
            "--md",
            *extra,
        ],
        cwd=ROOT,
        env={
            **os.environ,
            "APPSEC_CLAUDE_EXECUTABLE": str(stub),
            "FAKE_CLAUDE_STATE": str(state),
            "FAKE_CLAUDE_AUDIT_VERDICTS": str(VERDICTS),
            # API billing skips the subscription login check.
            "ANTHROPIC_API_KEY": "offline-test",
            "PATH": path,
        },
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result, output, state


@pytest.fixture(scope="module")
def full_audit(tmp_path_factory):
    return _audit(tmp_path_factory.mktemp("example-audit"), "--gate")


def _rows(output: Path) -> dict[str, dict]:
    document = json.loads((output / ".requirements-audit.json").read_text())
    return {row["id"]: row for row in document["results"]}


def _controls(node: dict):
    """Every control of a catalog or group, with its enhancements."""
    for group in node.get("groups", []):
        yield from _controls(group)
    for control in node.get("controls", []):
        yield control
        yield from _controls(control)


def _withdrawn(control: dict) -> bool:
    return any(p["name"] == "status" and p["value"] == "withdrawn" for p in control.get("props", []))


def test_the_expected_verdicts_cover_the_catalog_and_cite_real_fixture_lines():
    controls = list(_controls(json.loads(CATALOG.read_text())["catalog"]))
    verdicts = json.loads(VERDICTS.read_text())
    assert set(verdicts) == {control["id"] for control in controls if not _withdrawn(control)}
    for control_id, verdict in verdicts.items():
        for item in verdict["evidence"]:
            line = (FIXTURE / item["file"]).read_text().splitlines()[item["line"] - 1]
            assert item["shows"] in line, f"{control_id}: {item['file']}:{item['line']}"


def test_the_audit_grades_every_active_control_and_blocks_on_failed_controls(full_audit):
    result, output, _ = full_audit
    assert result.returncode == 1, result.stderr[-2000:]
    assert "Traceback" not in result.stderr
    public = json.loads(result.stdout)
    assert public["audit_status"] == "complete" and public["gate"] == "block"

    expected = json.loads(VERDICTS.read_text())
    rows = _rows(output)
    assert {key: row["status"] for key, row in rows.items()} == {key: row["status"] for key, row in expected.items()}
    assert rows["sec-1"]["evidence"] == [
        {"file": "server.js", "line": 9},
        {"file": "config/insecure-settings.ini", "line": 2},
    ]
    # OSCAL has no obligation level.
    assert {row["priority"] for row in rows.values()} == {"MUST"}
    assert "iam-8" not in rows

    counts = Counter(row["status"] for row in rows.values())
    assert counts == {"FAIL": 21, "UNVERIFIABLE": 5, "PASS": 1, "PARTIAL": 1, "NOT_APPLICABLE": 1}
    summary = public["summary"]
    assert (summary["fail"], summary["partial"], summary["pass"]) == (21, 1, 1)
    assert (summary["unverifiable"], summary["not_applicable"]) == (5, 1)


def test_the_audit_records_which_catalog_it_read(full_audit):
    _, output, _ = full_audit
    provenance = json.loads((output / ".requirements-audit.json").read_text())["provenance"]
    assert provenance["catalog_sha256"] == hashlib.sha256(CATALOG.read_bytes()).hexdigest()
    assert provenance["catalog_format"] == {
        "format": "oscal-catalog",
        "title": TITLE,
        "version": "3.2",
        "oscal_version": "1.1.2",
        "requirements": 29,
        "withdrawn_left_out": 1,
    }


def test_the_conversion_resolves_parameters_and_keeps_the_catalog_structure(full_audit):
    _, output, _ = full_audit
    rows = _rows(output)
    # A value set on the control and a value set for the whole catalog.
    assert rows["iam-3"]["requirement_text"] == (
        "Limit access tokens to a lifetime of 30 minutes and end a session after 15 minutes without activity."
    )
    # Choices and assignments the catalog leaves open stay visible as open.
    assert (
        "[Selection: Argon2id; scrypt; bcrypt with a cost factor of at least 12]" in rows["iam-2"]["requirement_text"]
    )
    assert (
        "[Selection (one or more): hardware security keys; passkeys; authenticator apps]"
        in rows["iam-1.1"]["requirement_text"]
    )
    assert "[Assignment: rotation interval in days, set by the system owner]" in rows["sec-3"]["requirement_text"]
    # Statement items stay in order with their labels.
    assert " a. enforce authentication" in rows["iam-1"]["requirement_text"]
    assert " b. reject a request" in rows["iam-1"]["requirement_text"]
    # Nested groups become one category titled with their path.
    assert rows["iam-5"]["category"] == "iam-authz"
    assert rows["iam-5"]["category_title"] == "Identity and Access Management / Authorization"


def test_the_model_gets_no_guidance_no_withdrawn_control_and_no_unmasked_secret(full_audit):
    _, _, state = full_audit
    prompts = (state / "audit-prompts.log").read_text()
    # What was sent: the requirements and the source lines the model asked for, the secret lines among them.
    assert "Require a verified identity on every route" in prompts
    assert "res.redirect(req.query.next)" in prompts
    assert "9: const secret = '****" in prompts and "2: password = " in prompts

    for control in _controls(json.loads(CATALOG.read_text())["catalog"]):
        for part in control.get("parts", []):
            if part["name"] == "guidance":
                assert part["prose"] not in prompts
    assert "Allow administrative functions only from the office network." not in prompts
    for secret in SECRETS:
        assert secret not in prompts


def test_the_report_names_the_catalog_and_lists_the_open_controls(full_audit):
    _, output, _ = full_audit
    report = (output / "appsec-requirements-report.md").read_text()
    assert f'Catalog format: OSCAL catalog "{TITLE}" 3.2 (OSCAL 1.1.2): 29 requirements, 1 withdrawn left out' in report
    for heading in ("## inp-2 · FAIL", "## iam-1 · PARTIAL", "## sec-3 · UNVERIFIABLE"):
        assert heading in report
    assert "## iam-4 ·" not in report
    assert "iam-8" not in report


def test_a_selected_part_of_the_catalog_without_failures_passes_the_gate(tmp_path):
    result, output, _ = _audit(tmp_path, "--gate", "--category", "iam-4")
    assert result.returncode == 0, result.stderr[-2000:]
    assert json.loads(result.stdout)["gate"] == "pass"
    assert {key: row["status"] for key, row in _rows(output).items()} == {"iam-4": "PASS", "iam-4.1": "UNVERIFIABLE"}


def test_a_profile_is_refused_before_any_model_call(tmp_path):
    metadata = json.loads(CATALOG.read_text())["catalog"]["metadata"]
    profile = tmp_path / "profile.json"
    profile.write_text(
        json.dumps({"profile": {"metadata": metadata, "imports": [{"href": "brennholt-appsec-catalog.oscal.json"}]}})
    )
    result, output, state = _audit(tmp_path, "--gate", catalog=profile)
    assert result.returncode == 2
    assert "OSCAL profile is not supported" in result.stderr
    assert "Traceback" not in result.stderr
    assert not (state / "calls.jsonl").exists()
    assert not list(output.iterdir())


def test_assess_carries_the_catalog_into_the_published_assessment(tmp_path):
    argv, env, out, _ = _system(tmp_path, ("solo",))
    result = _headless(argv, env, "--requirements", str(CATALOG))
    assert result.returncode == 0, result.stdout[-2000:] + result.stderr[-2000:]
    assert "Traceback" not in result.stderr
    _assert_published(out, 1)

    model = yaml.safe_load((out / "security-assessment.yaml").read_text())
    assert model["meta"]["check_requirements"] is True
    provenance = model["requirements_provenance"]
    assert provenance["count"] == 29
    assert provenance["converted_from"] == {
        "format": "oscal-catalog",
        "title": TITLE,
        "version": "3.2",
        "sha256": hashlib.sha256(CATALOG.read_bytes()).hexdigest(),
    }
    report = (out / "security-assessment.md").read_text()
    for control in ("iam-1.1", "sup-4.1", "pay-1"):
        assert control in report
    assert "iam-8" not in report
