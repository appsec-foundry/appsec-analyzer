"""Failures that must not turn into a clean-looking result: scans, source admission, publication."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import analyzers.config_iac_scanner as scanner
import pytest
import validators.qa_checks as qa
import validators.validate_intermediate as vi
from model import build_threat_model_yaml as builder
from runtime import source_preflight

from appsec_analyzer import copilot_cli

HELM_WORKLOAD = (
    "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: app\n{{- if .Values.x }}\n  labels: {}\n{{- end }}\n"
    "spec:\n  template:\n    spec:\n      containers:\n        - name: a\n          image: a:1\n"
    "          securityContext:\n            privileged: true\n"
)


def _repo(tmp_path: Path, manifest: str) -> Path:
    repo = tmp_path / "repo"
    (repo / "k8s").mkdir(parents=True)
    (repo / "k8s" / "deploy.yaml").write_text(manifest, encoding="utf-8")
    (repo / "Dockerfile").write_text("FROM node:20\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(
        ["git", "-C", str(repo), "-c", "user.name=T", "-c", "user.email=t@example.invalid", "commit", "-qm", "x"],
        check=True,
    )
    return repo


def test_a_manifest_the_checks_could_not_parse_is_named_not_counted_as_clean(tmp_path):
    result = scanner.scan(
        _repo(tmp_path, HELM_WORKLOAD), scanner.DEFAULT_CHECKS, depth="standard", output=tmp_path / "r"
    )
    assert result["unparsed_iac"] == {"file_count": 1, "files": ["k8s/deploy.yaml"]}
    assert not [row for row in result["findings"] if row["check_id"] in {"IAC-080", "IAC-081", "IAC-082"}]
    structured = [row for row in result["rules_evaluated"] if row["check_id"] in {"IAC-080", "IAC-081", "IAC-082"}]
    assert structured and all(row["status"] == "not_applicable" and row["files"] == 0 for row in structured)
    assert vi.validate_config_scan_findings(result) == (True, [])


def test_a_parsable_manifest_reports_no_unparsed_files(tmp_path):
    plain = HELM_WORKLOAD.replace("{{- if .Values.x }}\n  labels: {}\n{{- end }}\n", "")
    result = scanner.scan(_repo(tmp_path, plain), scanner.DEFAULT_CHECKS, depth="standard", output=tmp_path / "r")
    assert "unparsed_iac" not in result
    assert any(row["check_id"] == "IAC-080" for row in result["findings"])


def test_a_commit_that_could_not_be_read_does_not_make_two_runs_the_same_source():
    prior = {"current_sha": "unknown", "assessment_depth": "standard"}
    assert not builder._same_source(prior, "unknown", None)
    assert not builder._same_source(prior, None, None)


def test_the_captured_source_state_decides_whether_a_rerun_saw_the_same_source():
    prior = {"current_sha": "a" * 40, "source_state": "1" * 64}
    assert builder._same_source(prior, "a" * 40, "1" * 64)
    # Uncommitted changes keep the commit but change the state.
    assert not builder._same_source(prior, "a" * 40, "2" * 64)
    # An earlier entry without a state is not claimed to be the same source.
    assert not builder._same_source({"current_sha": "a" * 40}, "a" * 40, "1" * 64)
    # Without a state the commit still decides.
    assert builder._same_source({"current_sha": "a" * 40}, "a" * 40, None)


def test_changed_source_after_an_unreadable_commit_yields_new_findings_for_the_gate(tmp_path):
    cfg = {"mode": "full", "assessment_depth": "standard", "reasoning_model": "sonnet-economy"}
    comps = [{"id": "comp-a"}]
    first = builder.build_changelog(
        cfg, [{"id": "T-001", "component": "comp-a"}], comps, [], None, tmp_path, current_sha="unknown", run_id="1"
    )
    second = builder.build_changelog(
        cfg,
        [
            {"id": "T-001", "component": "comp-a"},
            {"id": "T-002", "component": "comp-a", "cwe": "CWE-79", "title": "XSS", "risk": "Critical"},
        ],
        comps,
        [],
        first,
        tmp_path,
        current_sha="unknown",
        run_id="2",
        source_state="2" * 64,
    )
    assert "T-002" in second[0]["added"]["threats"]


@pytest.mark.parametrize("name", ["pentest-tasks.yaml", "tasks-renamed.json", "extra.svg", "report.html"])
def test_the_delivery_gate_scans_every_text_file_whatever_its_name(tmp_path, name):
    (tmp_path / "security-assessment.md").write_text("clean prose\n", encoding="utf-8")
    (tmp_path / name).write_text("objective: key = AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    report = qa.check_published_secrets(tmp_path)
    assert any(name in issue for issue in report.issues)


def test_the_delivery_gate_passes_clean_files_and_skips_binary_ones(tmp_path):
    (tmp_path / "security-assessment.md").write_text("clean prose\n", encoding="utf-8")
    (tmp_path / "security-assessment.pdf").write_bytes(b"%PDF-1.7\xff\xfe\x00AKIAIOSFODNN7EXAMPLE")
    (tmp_path / "subdirectory").mkdir()
    assert qa.check_published_secrets(tmp_path).ok == 1


def test_the_delivery_gate_is_reachable_as_a_command(tmp_path, capsys):
    (tmp_path / "pentest-tasks.yaml").write_text("objective: AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8")
    assert qa.main(["qa_checks.py", "published_secrets", str(tmp_path)]) == 1
    assert json.loads(capsys.readouterr().out)["issues"]


@pytest.mark.parametrize(
    ("code", "expected", "forbidden"),
    [
        (3, "does not exist or cannot be read", "trust-mode"),
        (1, "could not run", "trust-mode"),
    ],
)
def test_a_preflight_that_gives_no_verdict_does_not_advise_trusting_the_repository(
    monkeypatch, code, expected, forbidden
):
    monkeypatch.setattr(
        source_preflight.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, code, stdout="", stderr="boom"),
    )
    with pytest.raises(source_preflight.SourcePreflightError) as raised:
        source_preflight.check_repositories(["/nonexistent"])
    assert expected in str(raised.value) and forbidden not in str(raised.value)


def test_a_preflight_verdict_about_the_repository_still_names_the_trust_mode(monkeypatch):
    monkeypatch.setattr(
        source_preflight.subprocess,
        "run",
        lambda *a, **k: subprocess.CompletedProcess(a, 2, stdout="", stderr="url found"),
    )
    with pytest.raises(source_preflight.SourcePreflightError, match="--trust-mode trusted"):
        source_preflight.check_repositories(["/repo"])


def test_a_controller_prompt_reaches_copilot(monkeypatch, tmp_path):
    from runtime.assessment_host import _prompt

    transport = copilot_cli.CopilotCliTransport(
        tmp_path, "gpt-5.4", "medium", {"executable": "copilot", "version": copilot_cli.SUPPORTED_VERSION}
    )
    seen = []

    def run(argv, **kwargs):
        seen.append(kwargs["data"])
        return 0, b'{"ok":true}', b""

    monkeypatch.setattr(copilot_cli, "_run", run)
    prompt = _prompt({"context": {"name": "artificial"}, "source_slices": []})
    schema = {
        "type": "object",
        "properties": {"ok": {"const": True}},
        "required": ["ok"],
        "additionalProperties": False,
    }
    assert transport.invoke("trusted", prompt, schema, 5, lambda: False).payload == {"ok": True}
    assert str(prompt).encode() in seen[0]


def test_failure_markers_do_not_match_inside_numbers_or_model_text():
    from runtime.analyst_host import _stderr_failure, contains_marker

    from appsec_analyzer import codex_cli

    assert contains_marker("http 429 too many", "429") and not contains_marker("request id 14290x", "429")
    assert codex_cli._failure([], b"processed 4290 files, 14031 rows", 1).reason != "authentication_failed"
    assert copilot_cli._failure(b"the answer mentions quota and 429", b"boom", 1).reason == "host_failure"
    assert copilot_cli._failure(b"usage limit", b"", 1).reason == "quota_exhausted"
    assert _stderr_failure(b"Error: 429 Too Many Requests")[0] == "rate_limit"


def _lockfile_result(tmp_path, with_manifest: bool):
    repo = _repo(tmp_path, "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: c\n")
    if with_manifest:
        (repo / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "package.json"], check=True)
    result = scanner.scan(repo, scanner.DEFAULT_CHECKS, depth="standard", output=tmp_path / "r")
    status = next(row["status"] for row in result["rules_evaluated"] if row["check_id"] == "IAC-050")
    return status, [row for row in result["findings"] if row["check_id"] == "IAC-050"]


def test_a_missing_lockfile_counts_only_where_the_repository_has_a_manifest(tmp_path):
    status, findings = _lockfile_result(tmp_path / "without", with_manifest=False)
    assert status == "not_applicable" and not findings
    status, findings = _lockfile_result(tmp_path / "with", with_manifest=True)
    assert status == "violated" and len(findings) == 1


def test_failed_post_processing_steps_are_named_in_the_report_meta(tmp_path):
    import yaml
    from orchestrator import orchestration_controller as controller

    path = tmp_path / "threat-model.yaml"
    path.write_text(
        yaml.safe_dump({"meta": {"unanalysed_source": [{"reason": "oversized", "files": 1, "examples": ["a"]}]}})
    )
    receipts = [
        f"model/b.py: {controller.BEST_EFFORT_FAILURE}",
        "other receipt",
        f"model/a.py: {controller.BEST_EFFORT_FAILURE}",
    ]
    controller._record_failed_steps(path, receipts)
    controller._record_failed_steps(path, receipts)
    rows = yaml.safe_load(path.read_text())["meta"]["unanalysed_source"]
    assert rows == [
        {"reason": "oversized", "files": 1, "examples": ["a"]},
        {"reason": "failed-step", "files": 2, "examples": ["model/a.py", "model/b.py"]},
    ]
    from renderers import pregenerate_fragments as fragments

    clause = fragments._unanalysed_clause(rows[1])
    assert "2 post-processing steps that failed" in clause and "`model/a.py`" in clause
    assert "1 file without read permission (`x`)" in fragments._unanalysed_clause(
        {"reason": "unreadable", "files": 1, "examples": ["x"]}
    )
