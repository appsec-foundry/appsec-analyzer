"""Separate requirements audit keeps source reads, verdicts, and gate bounded."""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from runtime.analyst_host import HostReply

from appsec_analyzer.requirements_audit import audit_repository


def _fixture(tmp_path: Path) -> tuple[Path, Path, Path]:
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "handler.py").write_text("def handler(user):\n    return user.data\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Test",
                    "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], check=True)
    output = tmp_path / "audit"
    output.mkdir()
    catalog = tmp_path / "catalog.yaml"
    catalog.write_text(
        "categories:\n  - id: CAT-AC\n    title: Access control\n    requirements:\n"
        "      - id: AC-1\n        priority: MUST\n        text: Protect account reads.\n",
        encoding="utf-8",
    )
    return repo, output, catalog


class FakeHost:
    def __init__(self, *, outside: bool = False):
        self.calls = 0
        self.outside = outside

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        self.calls += 1
        if self.calls == 1 and not self.outside:
            rid = re.search(r'"repository_id": "(repo-[0-9a-f]{16})"', prompt).group(1)
            return HostReply({"action": "read", "reads": [{"repository_id": rid,
                              "path": "handler.py", "start_line": 1, "end_line": 2}],
                              "artifact": None}, 0.01)
        return HostReply({"action": "complete", "reads": [], "artifact": {"results": [{
            "status": "FAIL", "evidence": [{"file": "outside.py" if self.outside else "handler.py", "line": 2}],
            "finding": "The handler returns data without an ownership check.",
            "fix": "Authorize the authenticated caller for the selected account.",
        }]}}, 0.01)


def test_audit_is_distinct_from_assessment_and_gate_is_deterministic(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    host = FakeHost()
    code, public = audit_repository(repo=str(repo), output=str(output), catalog_path=catalog,
                                    model="offline-fake", hard_budget=1, gate=True, write_md=True,
                                    host_factory=lambda ceiling: host)
    assert code == 1
    assert public["kind"] == "requirements-audit"
    assert public["assessment_status"] == "not_run"
    assert public["summary"]["fail"] == 1
    assert host.calls == 2
    verdict = json.loads((output / ".requirements-audit.json").read_text())
    assert verdict["results"][0]["id"] == "AC-1"
    assert verdict["results"][0]["evidence"] == [{"file": "handler.py", "line": 2}]
    assert (output / "appsec-requirements-report.md").is_file()


def test_audit_rejects_unserved_evidence_without_publishing(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    with pytest.raises(ValueError, match="Result rejected"):
        audit_repository(repo=str(repo), output=str(output), catalog_path=catalog,
                         model="offline-fake", hard_budget=1,
                         host_factory=lambda ceiling: FakeHost(outside=True))
    assert not (output / ".requirements-audit.json").exists()


def test_audit_rejects_output_inside_source(tmp_path: Path) -> None:
    repo, _output, catalog = _fixture(tmp_path)
    inside = repo / "reports"
    inside.mkdir()
    with pytest.raises(ValueError, match="separate"):
        audit_repository(repo=str(repo), output=str(inside), catalog_path=catalog,
                         model="offline-fake", hard_budget=1,
                         host_factory=lambda ceiling: FakeHost())


def test_audit_rejects_stale_verdict_before_model_call(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    (output / ".requirements-audit.json").write_text("old", encoding="utf-8")
    with pytest.raises(ValueError, match="fresh output"):
        audit_repository(repo=str(repo), output=str(output), catalog_path=catalog,
                         model="offline-fake", hard_budget=1,
                         host_factory=lambda ceiling: pytest.fail("host must not be called"))


def test_audit_rejects_invalid_model_and_catalog_symlink(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    with pytest.raises(ValueError, match="model identifier"):
        audit_repository(repo=str(repo), output=str(output), catalog_path=catalog,
                         model="../unsafe", hard_budget=1)
    link = tmp_path / "catalog-link.yaml"
    link.symlink_to(catalog)
    with pytest.raises(OSError):
        audit_repository(repo=str(repo), output=str(output), catalog_path=link,
                         model="offline-fake", hard_budget=1)
