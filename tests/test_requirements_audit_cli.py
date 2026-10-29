"""Separate requirements audit keeps source reads, verdicts, and gate bounded."""

from __future__ import annotations

import hashlib
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
    subprocess.run(
        [
            "git",
            "-C",
            str(repo),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
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
    def __init__(self, *, outside: bool = False, finding: str | None = None):
        self.calls = 0
        self.outside = outside
        self.finding = finding

    def invoke(self, system, prompt, schema, timeout_s, should_stop):
        self.calls += 1
        if self.calls == 1 and not self.outside:
            rid = re.search(r'"repository_id": "(repo-[0-9a-f]{16})"', prompt).group(1)
            return HostReply(
                {
                    "action": "read",
                    "reads": [{"repository_id": rid, "path": "handler.py", "start_line": 1, "end_line": 2}],
                    "artifact": None,
                },
                0.01,
            )
        return HostReply(
            {
                "action": "complete",
                "reads": [],
                "artifact": {
                    "results": [
                        {
                            "status": "FAIL",
                            "evidence": [{"file": "outside.py" if self.outside else "handler.py", "line": 2}],
                            "finding": self.finding or "The handler returns data without an ownership check.",
                            "fix": "Authorize the authenticated caller for the selected account.",
                        }
                    ]
                },
            },
            0.01,
        )


def _oscal(tmp_path: Path, root: str = "catalog") -> Path:
    path = tmp_path / "oscal.json"
    path.write_text(
        json.dumps(
            {
                root: {
                    "metadata": {"title": "Web baseline", "version": "1.2", "oscal-version": "1.1.2"},
                    "controls": [
                        {
                            "id": "ac-1",
                            "title": "Access",
                            "parts": [{"name": "statement", "prose": "Protect account reads."}],
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )
    return path


def test_audit_reads_an_oscal_catalog_and_records_its_format_and_checksum(tmp_path: Path) -> None:
    repo, output, _ = _fixture(tmp_path)
    catalog = _oscal(tmp_path)
    host = FakeHost()
    code, public = audit_repository(
        repo=str(repo),
        output=str(output),
        catalog_path=catalog,
        model="offline-fake",
        hard_budget=1,
        write_md=True,
        host_factory=lambda ceiling: host,
    )
    assert code == 0 and public["summary"]["fail"] == 1
    verdict = json.loads((output / ".requirements-audit.json").read_text())
    assert verdict["provenance"]["catalog_sha256"] == hashlib.sha256(catalog.read_bytes()).hexdigest()
    assert verdict["provenance"]["catalog_format"] == {
        "format": "oscal-catalog",
        "title": "Web baseline",
        "version": "1.2",
        "oscal_version": "1.1.2",
        "requirements": 1,
        "withdrawn_left_out": 0,
    }
    assert verdict["results"][0]["id"] == "ac-1" and verdict["results"][0]["priority"] == "MUST"
    markdown = (output / "appsec-requirements-report.md").read_text()
    assert 'Catalog format: OSCAL catalog "Web baseline" 1.2' in markdown


def test_audit_refuses_an_oscal_profile_before_any_model_call(tmp_path: Path) -> None:
    repo, output, _ = _fixture(tmp_path)
    host = FakeHost()
    with pytest.raises(ValueError, match="OSCAL profile is not supported"):
        audit_repository(
            repo=str(repo),
            output=str(output),
            catalog_path=_oscal(tmp_path, root="profile"),
            model="offline-fake",
            hard_budget=1,
            host_factory=lambda ceiling: host,
        )
    assert host.calls == 0 and not list(output.iterdir())


def test_audit_names_the_limit_and_the_category_filter_when_a_catalog_is_too_large(tmp_path: Path) -> None:
    repo, output, _ = _fixture(tmp_path)
    controls = [{"id": f"c-{n}", "parts": [{"name": "statement", "prose": "Do it."}]} for n in range(161)]
    path = tmp_path / "big.json"
    path.write_text(
        json.dumps(
            {"catalog": {"metadata": {"title": "t", "version": "1", "oscal-version": "1.1.2"}, "controls": controls}}
        )
    )
    host = FakeHost()
    with pytest.raises(
        ValueError, match=r"1 to 160 valid entries, found 161; select part of the catalog with --category"
    ):
        audit_repository(
            repo=str(repo),
            output=str(output),
            catalog_path=path,
            model="offline-fake",
            hard_budget=1,
            host_factory=lambda ceiling: host,
        )
    assert host.calls == 0


def test_audit_is_distinct_from_assessment_and_gate_is_deterministic(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    host = FakeHost()
    code, public = audit_repository(
        repo=str(repo),
        output=str(output),
        catalog_path=catalog,
        model="offline-fake",
        hard_budget=1,
        gate=True,
        write_md=True,
        host_factory=lambda ceiling: host,
    )
    assert code == 1
    assert public["kind"] == "requirements-audit"
    assert public["assessment_status"] == "not_run"
    assert public["summary"]["fail"] == 1
    assert host.calls == 2
    verdict = json.loads((output / ".requirements-audit.json").read_text())
    assert verdict["version"] == 2
    assert verdict["provenance"]["catalog_sha256"] == hashlib.sha256(catalog.read_bytes()).hexdigest()
    source = verdict["provenance"]["scope"]["repositories"][0]
    assert source["head"] == subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    assert source["files"][0]["path"] == "handler.py"
    assert source["files"][0]["sha256"] == hashlib.sha256((repo / "handler.py").read_bytes()).hexdigest()
    assert verdict["results"][0]["id"] == "AC-1"
    assert verdict["results"][0]["evidence"] == [{"file": "handler.py", "line": 2}]
    markdown = (output / "appsec-requirements-report.md").read_text(encoding="utf-8")
    assert f"Catalog SHA-256: {verdict['provenance']['catalog_sha256']}" in markdown
    assert f"Source HEAD: {source['head']}" in markdown


def test_audit_rejects_unmasked_secret_before_publishing_either_artifact(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    marker = "AKIA" + "A" * 16
    host = FakeHost(finding=f"Exposed {marker} in response.")
    with pytest.raises(ValueError, match="unmasked secret"):
        audit_repository(
            repo=str(repo),
            output=str(output),
            catalog_path=catalog,
            model="offline-fake",
            hard_budget=1,
            write_md=True,
            host_factory=lambda ceiling: host,
        )
    assert not (output / ".requirements-audit.json").exists()
    assert not (output / "appsec-requirements-report.md").exists()


@pytest.mark.parametrize("gate_on", ["fail", "partial"])
def test_unverifiable_is_never_counted_as_verified_pass(tmp_path: Path, gate_on: str) -> None:
    repo, output, catalog = _fixture(tmp_path)

    class UnverifiableHost:
        def invoke(self, system, prompt, schema, timeout_s, should_stop):
            return HostReply(
                {
                    "action": "complete",
                    "reads": [],
                    "artifact": {
                        "results": [
                            {
                                "status": "UNVERIFIABLE",
                                "evidence": [],
                                "finding": "Insufficient source evidence.",
                                "fix": "Provide evidence.",
                            }
                        ]
                    },
                },
                0.01,
            )

    code, public = audit_repository(
        repo=str(repo),
        output=str(output),
        catalog_path=catalog,
        model="offline-fake",
        hard_budget=1,
        gate=True,
        gate_on=gate_on,
        host_factory=lambda ceiling: UnverifiableHost(),
    )
    assert code == 0 and public["gate"] == "pass"
    assert public["summary"]["pass"] == 0
    assert public["summary"]["unverifiable"] == 1


def test_audit_rejects_secret_in_catalog_even_when_markdown_omits_row(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    marker = "AKIA" + "B" * 16
    catalog.write_text(catalog.read_text().replace("Protect account reads.", f"Protect {marker} account reads."))
    host = FakeHost()
    with pytest.raises(ValueError, match="unmasked secret"):
        audit_repository(
            repo=str(repo),
            output=str(output),
            catalog_path=catalog,
            model="offline-fake",
            hard_budget=1,
            write_md=True,
            host_factory=lambda ceiling: host,
        )
    assert not list(output.iterdir())


def test_audit_rejects_unserved_evidence_without_publishing(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    with pytest.raises(ValueError, match="Result rejected"):
        audit_repository(
            repo=str(repo),
            output=str(output),
            catalog_path=catalog,
            model="offline-fake",
            hard_budget=1,
            host_factory=lambda ceiling: FakeHost(outside=True),
        )
    assert not (output / ".requirements-audit.json").exists()


def test_audit_rejects_output_inside_source(tmp_path: Path) -> None:
    repo, _output, catalog = _fixture(tmp_path)
    inside = repo / "reports"
    inside.mkdir()
    with pytest.raises(ValueError, match="separate"):
        audit_repository(
            repo=str(repo),
            output=str(inside),
            catalog_path=catalog,
            model="offline-fake",
            hard_budget=1,
            host_factory=lambda ceiling: FakeHost(),
        )


def test_audit_rejects_stale_verdict_before_model_call(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    (output / ".requirements-audit.json").write_text("old", encoding="utf-8")
    with pytest.raises(ValueError, match="fresh output"):
        audit_repository(
            repo=str(repo),
            output=str(output),
            catalog_path=catalog,
            model="offline-fake",
            hard_budget=1,
            host_factory=lambda ceiling: pytest.fail("host must not be called"),
        )


def test_audit_rejects_invalid_model_and_catalog_symlink(tmp_path: Path) -> None:
    repo, output, catalog = _fixture(tmp_path)
    with pytest.raises(ValueError, match="model identifier"):
        audit_repository(repo=str(repo), output=str(output), catalog_path=catalog, model="../unsafe", hard_budget=1)
    link = tmp_path / "catalog-link.yaml"
    link.symlink_to(catalog)
    with pytest.raises(OSError):
        audit_repository(repo=str(repo), output=str(output), catalog_path=link, model="offline-fake", hard_budget=1)
