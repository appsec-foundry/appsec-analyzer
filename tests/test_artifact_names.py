"""One naming set per directory; published names for internal artifacts."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from shared import artifact_names as names  # noqa: E402


@pytest.mark.parametrize(
    "internal,published",
    [
        ("threat-model.md", "appsec-assessment.md"),
        ("threat-model.yaml", "appsec-assessment.yaml"),
        ("threat-model.figure1-dark.svg", "appsec-assessment.figure1-dark.svg"),
        ("threat-model.sarif.json", "appsec-assessment.sarif.json"),
        ("threat-model-changelog.jsonl", "appsec-assessment-changelog.jsonl"),
        ("threat-model-juice.md", "appsec-assessment-juice.md"),
        ("pentest-tasks.yaml", "pentest-tasks.yaml"),
        ("threat-modeling-context.md", "threat-modeling-context.md"),
    ],
)
def test_published_name(internal, published):
    assert names.published_name(internal) == published


def test_each_set_is_found_by_its_own_files(tmp_path):
    assert names.artifact_stem(tmp_path) is None
    assert names.model_path(tmp_path) == tmp_path / "appsec-assessment.yaml"
    (tmp_path / "threat-model.md").write_text("x")
    assert names.report_path(tmp_path) == tmp_path / "threat-model.md"
    assert names.model_path(tmp_path) == tmp_path / "threat-model.yaml"


def test_the_interim_security_assessment_set_is_not_read(tmp_path):
    (tmp_path / "security-assessment.yaml").write_text("x")
    (tmp_path / "security-assessment.md").write_text("x")
    assert names.artifact_stem(tmp_path) is None
    assert names.model_path(tmp_path) == tmp_path / "appsec-assessment.yaml"


def test_a_published_set_is_preferred_only_when_alone(tmp_path):
    (tmp_path / "appsec-assessment.yaml").write_text("x")
    assert names.report_path(tmp_path) == tmp_path / "appsec-assessment.md"
    (tmp_path / "threat-model.yaml").write_text("x")
    with pytest.raises(names.ArtifactSetError, match="both"):
        names.model_path(tmp_path)
