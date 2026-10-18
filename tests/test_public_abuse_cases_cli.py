"""Public abuse-cases command: read-only listing and detail through the engine, no model."""

from __future__ import annotations

import json
import subprocess

from appsec_analyzer import cli


def _repo(root):
    root.mkdir()
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    return root


def test_abuse_cases_is_discoverable_without_model(capsys):
    assert cli.main(["capabilities"]) == 0
    assert json.loads(capsys.readouterr().out)["abuse_cases"] == {"available": True, "model_calls": False}


def test_listing_names_origin_kind_and_title_and_leaves_the_repository_unchanged(tmp_path, capsys):
    repo = _repo(tmp_path / "repo")
    before = sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*"))
    assert cli.main(["abuse-cases", "--repo", str(repo), "--no-org-profile"]) == 0
    out = capsys.readouterr().out
    assert "AC-T-001" in out and "technical" in out and "AC-B-001" in out and "business" in out
    assert sorted(p.relative_to(repo).as_posix() for p in repo.rglob("*")) == before


def test_detail_reports_that_nothing_was_checked_without_an_assessment(tmp_path, capsys):
    repo = _repo(tmp_path / "repo")
    assert cli.main(["abuse-cases", "AC-B-001", "--repo", str(repo), "--no-org-profile"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("AC-B-001") and "NOT CHECKED" in out


def test_unknown_id_fails_without_a_traceback(tmp_path, capsys):
    repo = _repo(tmp_path / "repo")
    assert cli.main(["abuse-cases", "AC-NOPE-1", "--repo", str(repo), "--no-org-profile"]) == 1
    output = capsys.readouterr()
    assert not output.out and "unknown abuse case ID" in output.err and "Traceback" not in output.err


def test_organization_profile_and_opt_out_are_mutually_exclusive(tmp_path, capsys):
    try:
        cli.main(["abuse-cases", "--org-profile", str(tmp_path / "p.yaml"), "--no-org-profile"])
    except SystemExit as stop:
        assert stop.code == 2
    else:
        raise AssertionError("conflicting profile options must be refused")
