"""The standalone build contains only current resources, even when reused."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GUIDES = (
    "authnz-review.md",
    "security-assessment.md",
    "security-score.md",
    "threat-analyst.md",
    "configuration.md",
    "model-selection.md",
    "profiles.md",
    "providers.md",
    "headless-mode.md",
    "security-requirements-audit-skill.md",
    "threat-dragon-export.md",
    "local-release-preparation.md",
    "org-profiles.md",
    "organization-distributions.md",
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
    assert (package / "data" / "architecture-analysis-policy.md").is_file()
    probe = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import appsec_analyzer.score.service; import appsec_analyzer.analyze_threats.cli; import appsec_analyzer.assessment.console; import appsec_analyzer.preflight; assert 'appsec_analyzer.cli' not in sys.modules",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(build)},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert probe.returncode == 0, probe.stderr
    score_repo = tmp_path / "score-repository"
    score_repo.mkdir()
    (score_repo / "service.py").write_text("def service():\n    return 1\n")
    for args in (
        ["init", "-q"],
        ["add", "."],
        ["-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"],
    ):
        subprocess.run(["git", "-C", str(score_repo), *args], check=True, capture_output=True)
    result = subprocess.run(
        [sys.executable, "-m", "appsec_analyzer.cli", "score", str(score_repo), "--json"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(build)},
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 2, result.stderr
    import json

    score = json.loads(result.stdout)
    assert score["verdict"] == "undetermined" and score["score"] is None
    assert set(score["scanner_status"].values()) == {"complete"}
    assert not (package / "agents" / "appsec-stride-analyzer-v2.md").exists()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "appsec_analyzer.cli",
            "profiles",
            "validate",
            str(package / "examples/profiles/release.yaml"),
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(build), "XDG_CONFIG_HOME": str(tmp_path / "config")},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    result = subprocess.run(
        [sys.executable, "-m", "appsec_analyzer.cli", "profiles", "show", "codex-cli", "--max-calls", "25"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(build), "XDG_CONFIG_HOME": str(tmp_path / "config")},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    import json

    profile = json.loads(result.stdout)
    assert profile["adapter"] == "codex-cli" and profile["settings"]["budget"] is None
    assert profile["settings"]["max_calls"] == 25
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
    wheel_path = next(dist.glob("*.whl"))
    installed = tmp_path / "installed"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-deps",
            "--no-index",
            "--no-compile",
            "--target",
            str(installed),
            str(wheel_path),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=45,
        env={**os.environ, "PIP_CONFIG_FILE": os.devnull, "PIP_NO_INPUT": "1"},
    )
    assert result.returncode == 0, result.stderr
    result = subprocess.run(
        [str(installed / "bin/appsec-analyzer"), "score", str(score_repo), "--json"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(installed)},
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 2, result.stderr
    installed_score = json.loads(result.stdout)
    assert installed_score == score
    from tests.test_public_export_cli import _bundle

    saved = _bundle(tmp_path)
    result = subprocess.run(
        [str(installed / "bin/appsec-analyzer"), "review", str(saved), "--with", "codex", "--preview"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(installed)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    installed_skill = installed / "appsec_analyzer/skills/review-assessment/SKILL.md"
    assert installed_skill.read_text() in result.stdout
    assert str(installed / "appsec_analyzer/review_context.py") in result.stdout
    result = subprocess.run(
        [sys.executable, str(installed / "appsec_analyzer/review_context.py"), str(saved), "--id", "F-001"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(installed)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["found"]
    exported = tmp_path / "installed-export"
    result = subprocess.run(
        [
            str(installed / "bin/appsec-analyzer"),
            "export",
            "--assessment",
            str(saved),
            "--output",
            str(exported),
            "--formats",
            "yaml",
            "sarif",
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(installed)},
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["model_calls"] == 0
    assert (exported / "security-assessment.yaml").read_bytes() == (saved / "security-assessment.yaml").read_bytes()
    assert json.loads((exported / "security-assessment.sarif.json").read_text())["version"] == "2.1.0"
    focused_state = tmp_path / "focused-state"
    result = subprocess.run(
        [
            str(installed / "bin/appsec-analyzer"),
            "analyze-threats",
            "How should exports be protected?",
            "--design",
            "--repo",
            str(score_repo),
            "--no-context",
            "--preview",
            "--non-interactive",
            "--state-dir",
            str(focused_state),
        ],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(installed)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "Preview only" in result.stdout and not focused_state.exists()
    result = subprocess.run(
        [str(installed / "bin/appsec-analyzer"), "authnz-review", "--help"],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(installed)},
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert result.returncode == 0 and "--pentest-output-format" in result.stdout, result.stderr
    review_code = """
import json
import sys
from types import SimpleNamespace
from appsec_analyzer.authnz_review import review_repository
from appsec_analyzer.cli import _engine_imports
_engine_imports()
from runtime.analyst_host import HostReply
artifact = {"partial": False, "analyzed_at": "2026-10-18T00:00:00Z", "findings": [],
            "chain_findings": [], "stride_covered": []}
host = SimpleNamespace(invoke=lambda *args: HostReply(
    {"action": "complete", "reads": [], "artifact": artifact}, 0.01))
code, result = review_repository(repo=sys.argv[1], hard_budget=1, host_factory=lambda ceiling: host)
assert code == 0
print(json.dumps(result))
"""
    result = subprocess.run(
        [sys.executable, "-c", review_code, str(score_repo)],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(installed)},
        capture_output=True,
        text=True,
        timeout=45,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["kind"] == "authnz-review"
    with zipfile.ZipFile(wheel_path) as wheel:
        wheel_files = set(wheel.namelist())
    with tarfile.open(next(dist.glob("*.tar.gz"))) as source:
        source_files = {"/".join(name.split("/")[1:]) for name in source.getnames()}
    for files in (wheel_files, source_files):
        assert not any(path.endswith("runtime/version_status.py") for path in files)
        assert not any(path.endswith("runtime/plugin_read_gate.py") for path in files)
    assert "appsec_analyzer/docs/security-assessment.md" in wheel_files
    for relative in (
        "skills/analyze-threats/SKILL.md",
        "skills/analyze-threats/HELP.txt",
        "skills/analyze-threats/references/analysis-contract.md",
        "scripts/contexts/analyst_documents.py",
        "docs/authnz-review.md",
        "schemas/authnz-report.schema.json",
        "schemas/pentest-tasks.schema.yaml",
        "agents/appsec-authnz-analyzer.md",
        "docs/security-score.md",
        "scripts/analyzers/security_score.py",
        "data/security-score-indicators.yaml",
        "schemas/security-score.schema.yaml",
        "docs/profiles.md",
        "docs/providers.md",
        "data/model-profiles/lite.yaml",
        "data/model-profiles/bedrock.yaml",
        "data/scan-profiles/lite.yaml",
        "data/scan-profiles/bedrock.yaml",
        "schemas/provider-connections.schema.yaml",
        "examples/provider-connections.yaml",
        "data/model-catalog.yaml",
        "data/model-profiles/codex.yaml",
        "data/model-profiles/codex-cli.yaml",
        "data/scan-profiles/codex-cli.yaml",
        "schemas/scan-profile.schema.yaml",
        "schemas/model-profile.schema.yaml",
        "examples/profiles/release.yaml",
        "examples/model-profiles/team-sol.yaml",
        "schemas/organization-distribution.schema.yaml",
        "examples/organization-distribution/setup.cfg",
        "examples/organization-distribution/src/nordlicht_appsec/cli.py",
        "examples/organization-distribution/ci/gitlab-ci.yml.example",
    ):
        assert "appsec_analyzer/" + relative in wheel_files
        assert relative in source_files
    assert "appsec_analyzer/codex_cli.py" in wheel_files
    for relative in (
        "score/service.py",
        "score/calculation.py",
        "score/collection.py",
        "score/events.py",
        "score/render.py",
        "score/progress.py",
        "analyze_threats/cli.py",
        "analyze_threats/preparation.py",
        "assessment/request.py",
        "assessment/console.py",
        "scanners/execution.py",
        "engine.py",
        "artifacts.py",
        "catalogs.py",
        "model_roles.py",
    ):
        assert "appsec_analyzer/" + relative in wheel_files
        assert "appsec_analyzer/" + relative in source_files
    assert "appsec_analyzer/scoring.py" in wheel_files
    assert "appsec_analyzer/scoring.py" in source_files
    assert "appsec_analyzer/authnz_review.py" in wheel_files
    assert "appsec_analyzer/authnz_review.py" in source_files
    assert "SECURITY.md" in source_files
    assert "appsec_analyzer/codex_cli.py" in source_files
    assert "appsec_analyzer/scripts/runtime/multi_repo_scope.py" in wheel_files
    assert "appsec_analyzer/data/stride-analysis-policy.md" in wheel_files
    assert "appsec_analyzer/data/architecture-analysis-policy.md" in wheel_files
    assert "data/architecture-analysis-policy.md" in source_files
    assert "appsec_analyzer/agents/appsec-stride-analyzer-v2.md" not in wheel_files
    assert "scripts/runtime/multi_repo_scope.py" in source_files
    assert "agents/appsec-stride-analyzer-v2.md" not in source_files
