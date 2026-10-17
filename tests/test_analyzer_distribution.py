"""The standalone build contains only current resources, even when reused."""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDES = (
    "security-assessment.md",
    "threat-analyst.md",
    "configuration.md",
    "model-selection.md",
    "headless-mode.md",
    "security-requirements-audit-skill.md",
    "threat-dragon-export.md",
    "local-release-preparation.md",
    "org-profiles.md",
)


def test_reused_build_drops_retired_resources_and_keeps_guide_links(tmp_path: Path) -> None:
    source = tmp_path / "source"
    shutil.copytree(
        ROOT,
        source,
        ignore=shutil.ignore_patterns(
            ".git", ".venv", "build", "dist", "__pycache__", "*.egg-info", ".pytest_cache", ".coverage-data"
        ),
    )
    build = tmp_path / "build"
    package = build / "appsec_analyzer"
    retired = package / "scripts" / "runtime" / "version_status.py"
    retired.parent.mkdir(parents=True)
    retired.write_text("stale file", encoding="utf-8")
    other = package / "scripts" / "runtime" / "plugin_read_gate.py"
    other.write_text("stale file", encoding="utf-8")
    command = [sys.executable, "setup.py", "build_py", "--build-lib", str(build)]
    for _ in range(2):
        result = subprocess.run(command, cwd=source, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
    assert not retired.exists()
    assert not other.exists()
    assert (package / "scripts" / "runtime" / "multi_repo_scope.py").is_file()
    assert (package / "data" / "stride-analysis-policy.md").is_file()
    assert not (package / "agents" / "appsec-stride-analyzer-v2.md").exists()
    for name in GUIDES:
        guide = package / "docs" / name
        assert guide.is_file()
        for reference in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", guide.read_text(encoding="utf-8")):
            if ":" not in reference and not reference.startswith(("/", "#")):
                assert (guide.parent / reference).is_file(), (name, reference)
    entry = package / "skills" / "appsec-analyzer" / "SKILL.md"
    for reference in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", entry.read_text(encoding="utf-8")):
        if ":" not in reference and not reference.startswith(("/", "#")):
            assert (entry.parent / reference).is_file(), reference

    dist = tmp_path / "dist"
    archive_command = [
        sys.executable,
        "setup.py",
        "build",
        "--build-base",
        str(tmp_path / "archive-build"),
        "bdist_wheel",
        "--bdist-dir",
        str(tmp_path / "bdist"),
        "--dist-dir",
        str(dist),
        "sdist",
        "--dist-dir",
        str(dist),
    ]
    result = subprocess.run(archive_command, cwd=source, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    with zipfile.ZipFile(next(dist.glob("*.whl"))) as wheel:
        wheel_files = set(wheel.namelist())
    with tarfile.open(next(dist.glob("*.tar.gz"))) as source:
        source_files = {"/".join(name.split("/")[1:]) for name in source.getnames()}
    for files in (wheel_files, source_files):
        assert not any(path.endswith("runtime/version_status.py") for path in files)
        assert not any(path.endswith("runtime/plugin_read_gate.py") for path in files)
    assert "appsec_analyzer/docs/security-assessment.md" in wheel_files
    assert "appsec_analyzer/scripts/runtime/multi_repo_scope.py" in wheel_files
    assert "appsec_analyzer/data/stride-analysis-policy.md" in wheel_files
    assert "appsec_analyzer/agents/appsec-stride-analyzer-v2.md" not in wheel_files
    assert "scripts/runtime/multi_repo_scope.py" in source_files
    assert "agents/appsec-stride-analyzer-v2.md" not in source_files
