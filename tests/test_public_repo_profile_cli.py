"""Public repo-profile command: deterministic profile, no model, no writes to the target."""

from __future__ import annotations

import json
from pathlib import Path

from appsec_analyzer import cli


def _tree(root: Path) -> Path:
    root.mkdir()
    (root / "app").mkdir()
    (root / "app" / "main.py").write_text("print('x')\n")
    (root / "app" / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    (root / "node_modules").mkdir()
    (root / "node_modules" / "dep.js").write_text("module.exports = 1\n")
    return root


def test_repo_profile_is_discoverable_without_model(capsys):
    assert cli.main(["capabilities"]) == 0
    assert json.loads(capsys.readouterr().out)["repo_profile"] == {"available": True, "model_calls": False}


def test_profile_json_is_deterministic_and_leaves_the_target_unchanged(tmp_path, capsys):
    repo = _tree(tmp_path / "repo")
    before = sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*"))
    assert cli.main(["repo-profile", str(repo), "--json"]) == 0
    first = capsys.readouterr().out
    assert json.loads(first)
    assert sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*")) == before
    assert cli.main(["repo-profile", str(repo), "--json"]) == 0
    assert capsys.readouterr().out == first


def test_profile_text_names_the_directory(tmp_path, capsys):
    repo = _tree(tmp_path / "repo")
    assert cli.main(["repo-profile", str(repo)]) == 0
    assert capsys.readouterr().out.startswith("Repository profile")


def test_missing_directory_fails_without_a_traceback(tmp_path, capsys):
    assert cli.main(["repo-profile", str(tmp_path / "missing")]) == 1
    output = capsys.readouterr()
    assert not output.out and "not a directory" in output.err and "Traceback" not in output.err
