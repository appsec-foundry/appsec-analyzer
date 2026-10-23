"""Top-level and assess help: grouped commands, examples, and parsing that stays unchanged."""

from __future__ import annotations

import pytest

from appsec_analyzer import cli


def _registered(parser) -> set[str]:
    return set(next(action for action in parser._actions if action.dest == "command").choices)


def _help(capsys, *args: str) -> str:
    with pytest.raises(SystemExit) as stop:
        cli.main([*args, "--help"])
    assert stop.value.code == 0
    return capsys.readouterr().out


def test_every_registered_command_is_listed_in_exactly_one_group():
    listed = [name for _, entries in cli._COMMAND_GROUPS for name, _ in entries]
    assert len(listed) == len(set(listed))
    # "organization" exists only in organization distributions, where "distribution" does not.
    assert _registered(cli._parser()) == set(listed) - {"organization"}


def test_top_level_help_leads_with_assess_and_review_and_shows_examples(capsys):
    out = _help(capsys)
    assert out.index("Start here:") < out.index("  assess ") < out.index("  review ") < out.index("Quick checks")
    assert out.count("{") == 0, "the flat command list must not return"
    assert "appsec-analyzer assess --repo" in out and "appsec-analyzer review" in out
    assert "usage: appsec-analyzer [-h] <command> [options]" in out


def test_subcommand_usage_does_not_inherit_the_top_level_usage(capsys):
    out = _help(capsys, "score")
    assert out.startswith("usage: appsec-analyzer score ")
    assert "<command>" not in out.splitlines()[0]


def test_assess_help_groups_options_and_shows_examples(capsys):
    out = _help(capsys, "assess")
    titles = ["Scope:", "Output and exports:", "Cost and limits:", "Provider and models:", "Run control:"]
    positions = [out.index(title) for title in titles]
    assert positions == sorted(positions)
    assert "Examples:" in out and "--assessment-depth quick --budget 5" in out
    assert out.splitlines()[0].startswith("usage: appsec-analyzer assess --repo PATH")


def test_grouping_does_not_change_assess_parsing(tmp_path):
    ns = cli._parser().parse_args(
        ["assess", "--repo", str(tmp_path), "--budget", "5", "--assessment-depth", "quick", "--sarif", "--resume"]
    )
    assert (ns.hard_budget, ns.assessment_depth, ns.sarif, ns.resume) == (5.0, "quick", True, True)
    assert ns.explicit >= {"hard_budget", "assessment_depth"}


def test_assess_without_repo_stops_before_any_work(capsys, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("assess must not start without --repo")

    monkeypatch.setattr(cli, "_assess", forbidden)
    assert cli.main(["assess"]) == 2
    err = capsys.readouterr().err
    assert "assess needs --repo" in err and "assess --repo ." in err
    assert "--repo https://github.com/" in err and "--output ~/assessments/project" in err


def test_assess_with_repo_still_reaches_the_assessment(monkeypatch, tmp_path):
    monkeypatch.setattr(cli, "_assess", lambda ns: 0)
    assert cli.main(["assess", "--repo", str(tmp_path)]) == 0


def test_preflight_without_repo_keeps_its_default(monkeypatch):
    seen = []

    def record(ns):
        seen.append(ns.repo)
        return 0

    monkeypatch.setattr(cli, "_assess", record)
    assert cli.main(["preflight"]) == 0
    assert seen == [None]


def test_missing_command_still_fails(capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main([])
    assert stop.value.code == 2
    assert "required: <command>" in capsys.readouterr().err
