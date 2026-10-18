"""Public focused review exercises real scanners, boundaries and legacy exports offline."""

from __future__ import annotations

import json
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
import yaml
from jsonschema import Draft202012Validator
from runtime.analyst_host import HostReply

from appsec_analyzer import resource_root
from appsec_analyzer.authnz_review import review_repository
from appsec_analyzer.cli import main


@pytest.fixture
def source(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "routes.js").write_text(
        "const express = require('express');\n"
        "const app = express();\n"
        "app.get('/orders/:id', (req, res) => {\n"
        "  return res.json(Order.findById(req.params.id));\n"
        "});\n",
        encoding="utf-8",
    )
    for argv in (
        ["init", "-q"],
        ["add", "."],
        ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"],
    ):
        subprocess.run(["git", "-C", str(repo), *argv], check=True, capture_output=True)
    output = tmp_path / "review"
    output.mkdir(mode=0o700)
    return repo, output


class SignalHost:
    def __init__(self, mutate=None):
        self.mutate = mutate
        self.calls = 0
        self.context = None

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        self.calls += 1
        packet = json.loads(
            prompt.split("UNTRUSTED_ASSESSMENT_DATA\n", 1)[1].rsplit("\nUNTRUSTED_ASSESSMENT_DATA", 1)[0]
        )
        self.context = packet["context"]
        assert "tool-less" in system
        assert timeout_s <= 600
        report = {
            "partial": False,
            "analyzed_at": "2026-10-18T00:00:00Z",
            "findings": [],
            "chain_findings": [],
            "stride_covered": [],
        }
        if self.mutate:
            report = self.mutate(report, self.context)
        return HostReply({"action": "complete", "reads": [], "artifact": report}, 0.01)


def _run(source, host=None, **kwargs):
    repo, output = source
    host = host or SignalHost()
    return review_repository(
        repo=str(repo), output=str(output), hard_budget=1, host_factory=lambda ceiling: host, **kwargs
    )


def test_review_runs_real_scanners_retains_signals_and_exports_both_formats(source):
    repo, output = source
    before = (repo / "routes.js").read_bytes()
    host = SignalHost()
    code, document = _run(
        source, host, pentest_tasks=True, pentest_output_format="both", pentest_target="https://staging.example.invalid"
    )
    assert code == 0
    assert document["kind"] == "authnz-review" and document["assessment_status"] == "not_run"
    assert document["review_status"] == "complete" and document["gate"] == "advisory"
    assert document["report"]["findings"]  # Model omission cannot remove deterministic signals.
    assert host.calls == 1
    assert document["provenance"]["scope"]["repositories"][0]["head"]
    assert (repo / "routes.js").read_bytes() == before
    assert not (repo / "docs").exists()
    assert (
        json.loads((output / "authnz-review.json").read_text())
        == yaml.safe_load((output / "authnz-review.yaml").read_text())
        == document
    )
    tasks = json.loads((output / "pentest-tasks-authnz.json").read_text())
    assert tasks == yaml.safe_load((output / "pentest-tasks-authnz.yaml").read_text()) == document["pentest_tasks"]
    assert tasks["tasks"] and tasks["endpoints"]
    assert tasks["meta"]["target"]["base_url"] == "https://staging.example.invalid"
    assert all("test_strategy" in t and "success_criteria" in t and "stop_conditions" in t for t in tasks["tasks"])
    assert all(t["safety"]["read_only"] and t["threat_id"].startswith("AZ-") for t in tasks["tasks"])
    schema = yaml.safe_load((resource_root() / "schemas/pentest-tasks.schema.yaml").read_text())
    Draft202012Validator(schema).validate(tasks)
    assert all(path.stat().st_mode & 0o077 == 0 for path in output.iterdir())
    assert not (output / ".authnz-review.lock").exists()


def test_console_only_review_leaves_no_saved_artifacts(source):
    repo, output = source
    code, result = review_repository(repo=str(repo), host_factory=lambda ceiling: SignalHost(), hard_budget=1)
    assert code == 0 and result["output"] is None
    assert not list(output.iterdir())


def test_gate_fails_on_retained_high_findings_and_partial_is_never_clean(source):
    code, document = _run(source, gate=True)
    assert document["report"]["summary"]["high"] > 0
    assert code == 1 and document["gate"] == "block"
    repo, _ = source
    code, document = review_repository(
        repo=str(repo),
        gate=True,
        hard_budget=1,
        host_factory=lambda ceiling: SignalHost(lambda r, c: {**r, "partial": True}),
    )
    assert code == 2 and document["review_status"] == "partial" and document["gate"] == "block"


@pytest.mark.parametrize(
    "kind", ["outside", "fabricated-confirmation", "invented-requirement", "secret", "unknown-field", "downgrade"]
)
def test_untrusted_model_output_cannot_cross_report_boundaries(source, kind):
    def mutate(report, context):
        evidence = context["source_auth_findings"]["findings"][0]
        finding = {
            "id": "AZ-001",
            "title": "Object lookup",
            "severity": "High",
            "category": "idor",
            "cwe": "CWE-639",
            "stride": "Elevation of Privilege",
            "source": "scanner",
            "component_id": None,
            "evidence": [{"file": evidence["file"], "line": evidence["line"]}],
            "attack_path": "A caller selects another user's order.",
            "remediation": {"summary": "Enforce ownership.", "reference": "CWE-639 — Object authorization"},
            "requirement_id": None,
            "requirement_url": None,
        }
        if kind == "outside":
            finding["evidence"][0]["file"] = "../outside.js"
        if kind == "fabricated-confirmation":
            finding["source"] = "confirmed-instance"
        if kind == "invented-requirement":
            finding["requirement_id"] = "AC-INVENTED"
        if kind == "secret":
            finding["attack_path"] = "Exposed " + "AKIA" + "A" * 16
        if kind == "unknown-field":
            finding["execute"] = "untrusted-command"
        if kind == "downgrade":
            finding["severity"] = "Low"
        return {**report, "findings": [finding]}

    with pytest.raises(ValueError):
        _run(source, SignalHost(mutate))
    assert not list(source[1].iterdir())


@pytest.mark.parametrize("case", ["inside", "symlink", "broad-permissions", "occupied", "locked"])
def test_invalid_destinations_fail_before_model_call(source, tmp_path, case):
    repo, output = source
    if case == "inside":
        output = repo / "review"
        output.mkdir(mode=0o700)
    if case == "symlink":
        link = tmp_path / "link"
        link.symlink_to(output, target_is_directory=True)
        output = link
    if case == "broad-permissions":
        output.chmod(0o755)
    if case == "occupied":
        (output / "existing.md").write_text("keep this")
    if case == "locked":
        (output / ".authnz-review.lock").write_text("other run")
    host = SignalHost()
    with pytest.raises(ValueError):
        review_repository(repo=str(repo), output=str(output), host_factory=lambda ceiling: host)
    assert host.calls == 0
    if case == "occupied":
        assert (output / "existing.md").read_text() == "keep this"
    if case == "locked":
        assert (output / ".authnz-review.lock").read_text() == "other run"


def test_source_change_blocks_publication(source):
    def mutate(report, context):
        (source[0] / "routes.js").write_text("changed source\n")
        return report

    with pytest.raises(ValueError, match="changed"):
        _run(source, SignalHost(mutate))
    assert not list(source[1].iterdir())


def test_cancellation_releases_output_claim(source):
    def interrupt(report, context):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        _run(source, SignalHost(interrupt))
    assert not list(source[1].iterdir())


def test_save_uses_fresh_private_directory_outside_assessment(source, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    repo, _ = source
    code, document = review_repository(
        repo=str(repo), save=True, hard_budget=1, host_factory=lambda ceiling: SignalHost()
    )
    assert code == 0
    destination = Path(document["output"])
    assert destination.parent.name == "authnz-reviews"
    assert destination.stat().st_mode & 0o077 == 0
    assert not destination.is_relative_to(repo)


@pytest.mark.parametrize("format", ["json", "yaml"])
def test_public_cli_separates_machine_result_and_progress(source, monkeypatch, capsys, format):
    import appsec_analyzer.authnz_review as module
    import appsec_analyzer.hosts as hosts

    original = module.review_repository
    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)
    monkeypatch.setattr(
        module, "review_repository", lambda **kw: original(**kw, host_factory=lambda ceiling: SignalHost())
    )
    assert main(["authnz-review", "--repo", str(source[0]), "--budget", "1", f"--{format}"]) == 0
    captured = capsys.readouterr()
    result = json.loads(captured.out) if format == "json" else yaml.safe_load(captured.out)
    assert result["kind"] == "authnz-review"
    assert "Model budget limit: USD 1" in captured.err and "Cross-component" in captured.err
    assert "\x1b" not in captured.out


def test_exporter_can_reexport_saved_report_to_json_without_model(source):
    _run(source)
    output = source[1]
    target = output / "reexport.json"
    result = subprocess.run(
        [
            sys.executable,
            str(resource_root() / "scripts/renderers/render_pentest_tasks.py"),
            "--authnz",
            str(output / ".authnz-report.json"),
            "--route-inventory",
            str(output / ".route-inventory.json"),
            "--output",
            str(target),
            "--output-format",
            "json",
            "--dialect",
            "strix",
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    document = json.loads(target.read_text())
    assert document["meta"]["dialect"] == "strix" and document["tasks"]


@pytest.mark.parametrize("dialect", ["generic", "strix"])
def test_pentest_tasks_preserve_hypothesis_grouped_evidence_and_requirements(dialect):
    from renderers.render_pentest_tasks import _authnz_finding_to_merged, build_document

    evidence = [{"file": "api/a.js", "line": 3}, {"file": "api/b.js", "line": 8}]
    finding = {
        "id": "AZ-001",
        "title": "Review object permissions",
        "cwe": "CWE-639",
        "severity": "Medium",
        "source": "hypothesis",
        "evidence": evidence,
        "requirement_id": "AC-1",
        "requirement_url": "https://example.invalid/AC-1",
    }
    document = build_document(
        {"threats": [_authnz_finding_to_merged(finding)]}, dialect, ".authnz-report.json", None, "test"
    )
    task = document["tasks"][0]
    assert task["finding_source"] == "hypothesis"
    assert task["evidence"] == evidence and task["safety"]["scope"] == ["api/a.js", "api/b.js"]
    assert task["requirement_id"] == "AC-1" and task["requirement_url"] == finding["requirement_url"]
    Draft202012Validator(yaml.safe_load((resource_root() / "schemas/pentest-tasks.schema.yaml").read_text())).validate(
        document
    )


def test_concurrent_review_cannot_claim_same_output(source):
    inner = SignalHost()

    def compete(report, context):
        with pytest.raises(ValueError, match="in use"):
            _run(source, inner)
        return report

    code, _ = _run(source, SignalHost(compete))
    assert code == 0 and inner.calls == 0


def test_model_cannot_request_source_reads(source):
    class ReadHost:
        def invoke(self, system, prompt, schema, timeout_s, should_stop):
            return HostReply(
                {
                    "action": "read",
                    "artifact": None,
                    "reads": [
                        {"repository_id": "repo-0000000000000000", "path": "../secret", "start_line": 1, "end_line": 1}
                    ],
                },
                0.01,
            )

    with pytest.raises(ValueError, match="outside"):
        _run(source, ReadHost())
    assert not list(source[1].iterdir())


def test_catalog_is_explicit_validated_and_masked_before_model_use(source, tmp_path):
    marker = "AKIA" + "B" * 16
    catalog = tmp_path / "requirements.yaml"
    catalog.write_text(
        "categories:\n  - id: AC\n    title: Access control\n    requirements:\n"
        "      - id: AC-1\n        priority: MUST\n        text: Check object ownership; " + marker + "\n"
    )
    host = SignalHost()
    code, document = _run(source, host, requirements_path=catalog)
    assert code == 0 and document["provenance"]["catalog_sha256"]
    assert marker not in json.dumps(host.context)
    assert marker not in json.dumps(document)
    assert host.context["requirements"]["categories"][0]["requirements"][0]["id"] == "AC-1"


@pytest.mark.parametrize("contents", ["!!python/object/apply:os.system ['unexpected']", "categories: not-an-array"])
def test_invalid_catalog_never_reaches_model(source, tmp_path, contents):
    catalog = tmp_path / "requirements.yaml"
    catalog.write_text(contents)
    host = SignalHost()
    with pytest.raises(ValueError):
        _run(source, host, requirements_path=catalog)
    assert host.calls == 0 and not list(source[1].iterdir())


@pytest.mark.parametrize("failure", ["timeout", "exit", "malformed"])
def test_scanner_failures_prevent_model_use_and_publication(source, monkeypatch, failure):
    import appsec_analyzer.authnz_review as module

    original = module.subprocess.run

    def scanner_call(argv, **kwargs):
        if len(argv) > 1 and str(argv[1]).endswith("/analyzers/route_inventory.py"):
            if failure == "timeout":
                raise subprocess.TimeoutExpired(argv, 120)
            if failure == "exit":
                return subprocess.CompletedProcess(argv, 1)
            result = original(argv, **kwargs)
            (Path(kwargs["cwd"]) / ".route-inventory.json").write_text("{broken")
            return result
        return original(argv, **kwargs)

    monkeypatch.setattr(module.subprocess, "run", scanner_call)
    host = SignalHost()
    with pytest.raises(ValueError):
        _run(source, host)
    assert host.calls == 0 and not list(source[1].iterdir())


def test_cli_reports_cancellation_and_safe_actionable_failures(source, monkeypatch, capsys):
    import appsec_analyzer.authnz_review as module
    import appsec_analyzer.hosts as hosts

    monkeypatch.setattr(hosts, "claude_preflight", lambda: None)

    def interrupt(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(module, "review_repository", interrupt)
    assert main(["authnz-review"]) == 130
    assert "cancelled" in capsys.readouterr().err

    def invalid(**kwargs):
        raise module.ReviewError("AuthNZ output must be empty; select a fresh private directory")

    monkeypatch.setattr(module, "review_repository", invalid)
    assert main(["authnz-review"]) == 2
    captured = capsys.readouterr()
    assert "must be empty" in captured.err and not captured.out

    def fail(**kwargs):
        raise ValueError("internal source: " + "AKIA" + "C" * 16)

    monkeypatch.setattr(module, "review_repository", fail)
    assert main(["authnz-review"]) == 2
    captured = capsys.readouterr()
    assert "AKIA" not in captured.err and "Traceback" not in captured.err and not captured.out


def test_markdown_encodes_active_markup_and_terminal_controls():
    from appsec_analyzer.authnz_review import markdown

    finding = {
        "id": "AZ-001",
        "severity": "High",
        "title": "<script>alert(1)</script>",
        "source": "hypothesis",
        "attack_path": "![leak](https://example.invalid/x)\n## injected\x1b[2J",
        "evidence": [{"file": "api/a.js", "line": 3}],
        "remediation": {"summary": "Check authorization", "reference": "CWE-639"},
    }
    document = {
        "report": {
            "summary": dict.fromkeys(("critical", "high", "medium", "low"), 0),
            "findings": [finding],
            "chain_findings": [],
            "partial": False,
        },
        "review_status": "complete",
        "gate": "advisory",
        "limitations": [],
        "output": None,
    }
    rendered = markdown(document)
    assert "<script>" not in rendered and "&lt;script&gt;" in rendered
    assert "![leak]" not in rendered and "\n## injected" not in rendered and "\x1b" not in rendered


def test_coverage_counts_are_derived_outside_model(source):
    fabricated = {"fake-component": {"total_routes": 999, "authenticated": 999, "unauthenticated": 0, "unknown": 0}}
    host = SignalHost(lambda report, context: {**report, "auth_coverage": fabricated})
    _, document = _run(source, host)
    coverage = document["coverage"]
    actual = document["report"]["auth_coverage"]
    assert "fake-component" not in actual
    assert actual["application"]["authenticated"] == coverage["authenticated_count"]
    assert actual["application"]["unauthenticated"] == coverage["authn_absent_count"]
    assert actual["application"]["unknown"] == coverage["authn_unknown_count"]


@pytest.mark.parametrize("through_link", [False, True])
def test_default_data_directory_inside_source_is_rejected_before_creation(source, monkeypatch, tmp_path, through_link):
    repo, _ = source
    data = repo / "data"
    selected = data
    if through_link:
        link = tmp_path / "alias"
        link.symlink_to(repo, target_is_directory=True)
        selected = link / "data"
    monkeypatch.setenv("XDG_DATA_HOME", str(selected))
    host = SignalHost()
    with pytest.raises(ValueError, match="inside the source"):
        review_repository(repo=str(repo), save=True, host_factory=lambda ceiling: host)
    assert not data.exists() and host.calls == 0


def test_temporary_storage_inside_source_is_rejected_before_scanners(source, monkeypatch):
    import tempfile

    repo, _ = source
    before = sorted(repo.iterdir())
    monkeypatch.setattr(tempfile, "tempdir", str(repo))
    host = SignalHost()
    with pytest.raises(ValueError, match="temporary storage"):
        review_repository(repo=str(repo), host_factory=lambda ceiling: host)
    assert sorted(repo.iterdir()) == before and host.calls == 0


def test_help_matches_authnz_guide_and_all_documented_commands_parse(capsys):
    from appsec_analyzer.cli import _parser

    with pytest.raises(SystemExit) as exited:
        main(["authnz-review", "--help"])
    assert exited.value.code == 0
    help_text = capsys.readouterr().out
    assert "--json" in help_text and "--yaml" in help_text
    assert "--pentest-tasks" in help_text and "--pentest-output-format" in help_text
    guide = (resource_root() / "docs/authnz-review.md").read_text()
    mentioned = set(re.findall(r"--[a-z][a-z-]*", guide))
    helper_flags = {"--authnz", "--route-inventory", "--output-format", "--dialect"}
    assert mentioned <= set(re.findall(r"--[a-z][a-z-]*", help_text)) | helper_flags
    commands = 0
    for block in re.findall(r"```sh\n(.*?)```", guide, re.S):
        for line in block.replace("\\\n", " ").splitlines():
            arguments = shlex.split(line)
            if arguments[:2] == ["appsec-analyzer", "authnz-review"]:
                assert _parser().parse_args(arguments[1:]).command == "authnz-review"
                commands += 1
    assert commands >= 5
